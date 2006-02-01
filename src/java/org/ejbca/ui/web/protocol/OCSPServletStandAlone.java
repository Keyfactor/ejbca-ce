package org.ejbca.ui.web.protocol;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.OCSPException;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 * 
 * @web.servlet name = "OCSP"
 *              display-name = "OCSPServletStandAlone"
 *              description="Answers OCSP requests"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/ocsp"
 *
 * @web.servlet-init-param description="Algorithm used by server to generate signature on OCSP responses"
 *   name="SignatureAlgorithm"
 *   value="SHA1WithRSA"
 *   
 * @web.servlet-init-param description="If set to true the servlet will enforce OCSP request signing"
 *   name="enforceRequestSigning"
 *   value="false"
 *   
 * @web.servlet-init-param description="If set to true the certificate chain will be returned with the OCSP response"
 *   name="includeCertChain"
 *   value="true"
 *   
 * @web.servlet-init-param description="If set to true the OCSP reponses will be signed directly by the CAs certificate instead of the CAs OCSP responder"
 *   name="useCASigningCert"
 *   value="${ocsp.usecasigningcert}"
 *   
 * @web.servlet-init-param description="Specifies the subject of a certificate which is used to identifiy the responder which will generate responses when no real CA can be found from the request. This is used to generate 'unknown' responses when a request is received for a certificate that is not signed by any CA on this server"
 *   name="defaultResponderID"
 *   value="${ocsp.defaultresponder}"
 *
 * @web.servlet-init-param description="Directory name of the soft keystores. The signing keys will be fetched from all files in this directory. Valid formats of the files are JKS and PKCS12 (p12)."
 *   name="softKeyDirectoryName"
 *   value="./softKeys"
 *
 * @web.servlet-init-param description="Signing key password. Must be same for all signing keys."
 *   name="keyPassword"
 *   value="foo123"
 *
 * @web.servlet-init-param description="Keystore password. Keystore password for all keystores in the keystore directory."
 *   name="storePassword"
 *   value="foo123"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @author Lars Silvén PrimeKey
 * @version  $Id: OCSPServletStandAlone.java,v 1.4 2006-02-01 22:34:54 primelars Exp $
 */
public class OCSPServletStandAlone extends OCSPServletBase {

    private ICertificateStoreOnlyDataSessionLocal mCertStore;
    private String mSoftKeyStoreDirectoryName;
    private char mKeyPassword[];
    private char mStorePassword[];
    private final Map mSignEntity;

    public OCSPServletStandAlone() {
        super();
        mSignEntity = new HashMap();
    }
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            {
                ServiceLocator locator = ServiceLocator.getInstance();
                ICertificateStoreOnlyDataSessionLocalHome castorehome =
                    (ICertificateStoreOnlyDataSessionLocalHome)locator.getLocalHome(ICertificateStoreOnlyDataSessionLocalHome.COMP_NAME);
                mCertStore = castorehome.create();
            }
            {
                final String keyPassword = config.getInitParameter("keyPassword");
                mKeyPassword = keyPassword!=null ? keyPassword.toCharArray() : null;
            }
            if ( mKeyPassword==null || mKeyPassword.length==0 )
                throw new ServletException("no keystore password given");
            {
                final String storePassword = config.getInitParameter("storePassword");
                mStorePassword = storePassword!=null ? storePassword.toCharArray() : null;
            }
            if ( mStorePassword==null || mStorePassword.length==0 )
                mStorePassword = mKeyPassword;
            mSoftKeyStoreDirectoryName = config.getInitParameter("softKeyDirectoryName");
            if ( mSoftKeyStoreDirectoryName!=null && mSoftKeyStoreDirectoryName.length()>0 )
                return; // the keys are soft.
            // add paramter initialization for HW keys here
            throw new ServletException("no valid keys spicified");
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
            m_log.error("Unable to initialize OCSPServlet.", e);
            throw new ServletException(e);
        }
    }
    void loadPrivateKeys(Admin adm) throws ServletException, IOException {
        File dir = new File(mSoftKeyStoreDirectoryName);
        if ( dir.isDirectory()==false )
            new ServletException(mSoftKeyStoreDirectoryName + " is not a directory.");
        File files[] = dir.listFiles();
        if ( files.length==0 )
            throw new ServletException("No files in mKey direktory: " + mSoftKeyStoreDirectoryName);
        for ( int i=0; i<files.length; i++ ) {
            final String fileName = files[i].getCanonicalPath();
            final Enumeration eAlias;
            final KeyStore keyStore;
            try {
                KeyStore tmpKeyStore;
                try {
                    tmpKeyStore = KeyStore.getInstance("JKS");
                    tmpKeyStore.load(new FileInputStream(fileName), mStorePassword);
                } catch( IOException e ) {
                    tmpKeyStore = KeyStore.getInstance("PKCS12");
                    tmpKeyStore.load(new FileInputStream(fileName), mStorePassword);
                }
                keyStore = tmpKeyStore;
                eAlias = keyStore.aliases();
            } catch( Exception e ) {
                m_log.error("Unable to load file "+fileName+". Exception: "+e.getMessage());
                continue;
            }
            while( eAlias.hasMoreElements() ) {
                final String alias = (String)eAlias.nextElement();
                try {
                    final PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, mKeyPassword);
                    if ( privateKey==null )
                        continue;
                    final X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                    RevokedCertInfo revokedInfo = isRevoked(adm, cert.getIssuerDN().getName(),
                                                            cert.getSerialNumber());
                    String sDebug = "Signing certificate with serial number "+cert.getSerialNumber() + " from issuer " + cert.getIssuerDN();
                    if ( revokedInfo==null ) {
                        m_log.error(sDebug + " can not be found.");
                        continue;
                    }
                    if ( revokedInfo.getReason()!=RevokedCertInfo.NOT_REVOKED ) {
                        m_log.error(sDebug + " revoked.");
                        continue;
                    }
                    X509Certificate chain[] = null; {
                        final List list = new ArrayList();
                        X509Certificate current = cert;
                        while( true ) {
                            list.add(current);
                            if ( (current.getIssuerX500Principal())==current.getSubjectX500Principal() ) {
                                chain = (X509Certificate[])list.toArray(new X509Certificate[0]);
                                break;
                            }
                            Iterator j = m_cacerts.iterator();
                            boolean isNotFound = true;
                            while( isNotFound && j.hasNext() ) {
                                X509Certificate target = (X509Certificate)j.next();
                                if ( current.getIssuerX500Principal()==target.getSubjectX500Principal() ) {
                                    current = target;
                                    isNotFound = false;
                                }
                            }
                            if ( isNotFound )
                                break;
                        }
                    }
                    if ( chain==null ) {
                        m_log.error(sDebug + " certificate chain broken.");
                        continue;
                    }
                    mSignEntity.put( new Integer(getCaid(chain[1])),
                                     new SigningEntity(chain, privateKey) );
                } catch (Exception e) {
                    m_log.error("Unable to get alias "+alias+" in file "+fileName+". Exception: "+e.getMessage());
                }
            }
        }
        if ( mSignEntity.size()==0 )
            m_log.error("No valid keys in direktory " + mSoftKeyStoreDirectoryName);
    }

    private class SigningEntity {
        final private X509Certificate mChain[];
        final private PrivateKey mKey;
        SigningEntity(X509Certificate c[], PrivateKey k) {
            mChain = c;
            mKey = k;
        }
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException {
            final BasicOCSPRespGenerator ocsprespgen = ((OCSPCAServiceRequest)request).getOCSPrespGenerator();
            final String sigAlg = ((OCSPCAServiceRequest)request).getSigAlg();
            final X509Certificate[] chain = ((OCSPCAServiceRequest)request).includeChain() ? mChain : null;
            try {
                final BasicOCSPResp ocspresp = ocsprespgen.generate(sigAlg, mKey, chain, new Date(), "BC" );
                return new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));             
            } catch (OCSPException ocspe) {
                throw new ExtendedCAServiceRequestException(ocspe);
            } catch (NoSuchProviderException nspe) {
                throw new ExtendedCAServiceRequestException(nspe);            
            }
        }
    }

    Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return mCertStore.findCertificatesByType(adm, type, issuerDN);
    }

    OCSPCAServiceResponse extendedService(Admin adm, int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException,
                                                                                                    ExtendedCAServiceNotActiveException {
        SigningEntity se =(SigningEntity)mSignEntity.get(new Integer(caid));
        if ( se!=null )
            return se.sign(request);
        else
            throw new ExtendedCAServiceNotActiveException("no ocsp signing mKey for cert "+caid);
    }

    RevokedCertInfo isRevoked(Admin adm, String name, BigInteger serialNumber) {
        return mCertStore.isRevoked(adm, name, serialNumber);
    }

}
