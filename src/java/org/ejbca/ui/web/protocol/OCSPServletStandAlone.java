/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.protocol;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
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

import org.apache.log4j.Logger;
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
 * @web.servlet-init-param description="Directory name of the soft keystores. The signing keys will be fetched from all files in this directory. Valid formats of the files are JKS and PKCS12 (p12)."
 *   name="softKeyDirectoryName"
 *   value="${ocsp.softKeys.dir}"
 *
 * @web.servlet-init-param description="Signing key password. Must be same for all signing keys."
 *   name="keyPassword"
 *   value="${ocsp.softKeys.keyPassword}"
 *
 * @web.servlet-init-param description="Keystore password. Keystore password for all keystores in the keystore directory."
 *   name="storePassword"
 *   value="${ocsp.softKeys.storePassword}"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @author Lars Silvén PrimeKey
 * @version  $Id: OCSPServletStandAlone.java,v 1.10 2006-02-08 07:31:49 anatom Exp $
 */
public class OCSPServletStandAlone extends OCSPServletBase {

    static private Logger m_log = Logger.getLogger(OCSPServletStandAlone.class);

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
    
    protected void loadPrivateKeys(Admin adm) throws ServletException, IOException {
        mSignEntity.clear();
        File dir = new File(mSoftKeyStoreDirectoryName);
        if ( dir==null || dir.isDirectory()==false )
            throw new ServletException(dir.getCanonicalPath() + " is not a directory.");
        File files[] = dir.listFiles();
        if ( files==null || files.length==0 )
            throw new ServletException("No files in soft key directory: " + dir.getCanonicalPath());
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
                    tmpKeyStore = KeyStore.getInstance("PKCS12", "BC");
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
                            if ( current.getIssuerX500Principal().equals(current.getSubjectX500Principal()) ) {
                                chain = (X509Certificate[])list.toArray(new X509Certificate[0]);
                                break;
                            }
                            Iterator j = m_cacerts.iterator();
                            boolean isNotFound = true;
                            while( isNotFound && j.hasNext() ) {
                                X509Certificate target = (X509Certificate)j.next();
                                m_log.debug( "curent issuer '" + current.getIssuerX500Principal()
                                             + "'. target subject: '" + target.getSubjectX500Principal() + "'.");
                                if ( current.getIssuerX500Principal().equals(target.getSubjectX500Principal()) ) {
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
            throw new ServletException("No valid keys in directory " + dir.getCanonicalPath());
    }

    private class SigningEntity {
        final private X509Certificate mChain[];
        final private PrivateKey mKey;
        SigningEntity(X509Certificate c[], PrivateKey k) {
            mChain = c;
            mKey = k;
        }
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException {
            final BasicOCSPRespGenerator ocsprespgen = (request).getOCSPrespGenerator();
            final String sigAlg = (request).getSigAlg();
            m_log.debug("signing algorithm: "+sigAlg);
            final X509Certificate[] chain = (request).includeChain() ? mChain : null;
            try {
                final BasicOCSPResp ocspresp = ocsprespgen.generate(sigAlg, mKey, chain, new Date(), "BC" );
                m_log.debug("The OCSP response is "
                            + (ocspresp.verify(chain[0].getPublicKey(), "BC") ? "" : "NOT ") + "verifying.");
                return new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));             
            } catch (OCSPException ocspe) {
                throw new ExtendedCAServiceRequestException(ocspe);
            } catch (NoSuchProviderException nspe) {
                throw new ExtendedCAServiceRequestException(nspe);            
            }
        }
    }

    protected Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return mCertStore.findCertificatesByType(adm, type, issuerDN);
    }

    protected Certificate findCertificateByIssuerAndSerno(Admin adm, String issuer, BigInteger serno) {
        return mCertStore.findCertificateByIssuerAndSerno(adm, issuer, serno);
    }
    
    protected OCSPCAServiceResponse extendedService(Admin adm, int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException,
                                                                                                    ExtendedCAServiceNotActiveException {
        SigningEntity se =(SigningEntity)mSignEntity.get(new Integer(caid));
        if ( se!=null ) {
            return se.sign(request);            
        }
        throw new ExtendedCAServiceNotActiveException("no ocsp signing key for caid "+caid);
    }

    protected RevokedCertInfo isRevoked(Admin adm, String name, BigInteger serialNumber) {
        return mCertStore.isRevoked(adm, name, serialNumber);
    }

}
