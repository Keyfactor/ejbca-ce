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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
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
 *   value="${ocsp.keys.dir}"
 *
 * @web.servlet-init-param description="Signing key password. Must be same for all signing keys."
 *   name="keyPassword"
 *   value="${ocsp.keys.keyPassword}"
 *
 * @web.servlet-init-param description="Keystore password. Keystore password for all keystores in the keystore directory."
 *   name="storePassword"
 *   value="${ocsp.keys.storePassword}"
 *
 * @web.servlet-init-param description="Keystore password. Keystore password for all keystores in the keystore directory."
 *   name="cardPassword"
 *   value="${ocsp.keys.cardPassword}"
 *
 * @web.servlet-init-param description="Keystore password. Keystore password for all keystores in the keystore directory."
 *   name="hardTokenClassName"
 *   value="${ocsp.hardToken.className}"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @author Lars Silvén PrimeKey
 * @version  $Id: OCSPServletStandAlone.java,v 1.17 2006-06-30 17:06:59 primelars Exp $
 */
public class OCSPServletStandAlone extends OCSPServletBase {

    static final protected Logger m_log = Logger.getLogger(OCSPServletStandAlone.class);

    private ICertificateStoreOnlyDataSessionLocal mCertStore;
    private String mKeystoreDirectoryName;
    private char mKeyPassword[];
    private char mStorePassword[];
    private CardKeys mHardTokenObject;
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
            if ( mHardTokenObject==null ) {
                final String hardTokenClassName = config.getInitParameter("hardTokenClassName");
                if ( hardTokenClassName!=null && hardTokenClassName.length()>0 ) {
                    String sCardPassword = config.getInitParameter("cardPassword");
                    sCardPassword = sCardPassword!=null ? sCardPassword.trim() : null;
                    if ( sCardPassword!=null && sCardPassword.length()>0 ) {
                        try {
                            mHardTokenObject = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(hardTokenClassName).newInstance();
                            mHardTokenObject.autenticate(sCardPassword);
                        } catch( ClassNotFoundException e) {
                            m_log.info("Class " + hardTokenClassName + " could not be loaded.");
                        }
                    } else
                        m_log.info("No card password specified.");
                } else
                    m_log.info("No HW OCSP signing class defined.");
            }
            if ( mStorePassword==null || mStorePassword.length==0 )
                mStorePassword = mKeyPassword;
            mKeystoreDirectoryName = config.getInitParameter("softKeyDirectoryName");
            if ( mKeystoreDirectoryName!=null && mKeystoreDirectoryName.length()>0 )
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
    private X509Certificate[] getCertificateChain(X509Certificate cert, Admin adm) {
        RevokedCertInfo revokedInfo = isRevoked(adm, cert.getIssuerDN().getName(),
                cert.getSerialNumber());
        String sDebug = "Signing certificate with serial number "+cert.getSerialNumber() + " from issuer " + cert.getIssuerDN();
        if ( revokedInfo==null ) {
            m_log.error(sDebug + " can not be found.");
            return null;
        }
        if ( revokedInfo.getReason()!=RevokedCertInfo.NOT_REVOKED ) {
            m_log.error(sDebug + " revoked.");
            return null;
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
                    m_log.debug( "curent issuer '" + current.getIssuerX500Principal() +
                            "'. target subject: '" + target.getSubjectX500Principal() + "'.");
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
            m_log.debug(sDebug + " certificate chain broken.");
        }
        return chain;
    }
    private boolean loadFromKeyStore(Admin adm, String fileName) {
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
            m_log.debug("Unable to load file "+fileName+". Exception: "+e.getMessage());
            return false;
        }
        while( eAlias.hasMoreElements() ) {
            final String alias = (String)eAlias.nextElement();
            try {
                putSignEntity(new PrivateKeyFactorySW((PrivateKey)keyStore.getKey(alias, mKeyPassword)),
                		(X509Certificate)keyStore.getCertificate(alias), adm, "BC");
            } catch (Exception e) {
                m_log.debug("Unable to get alias "+alias+" in file "+fileName+". Exception: "+e.getMessage());
            }
        }
        return true;
    }
    private boolean putSignEntity( PrivateKeyFactory keyFactory, X509Certificate cert, Admin adm, String providerName ) {
        if ( keyFactory!=null && cert!=null ) {
            X509Certificate[] chain = getCertificateChain(cert, adm);
            if ( chain!=null )
                mSignEntity.put( new Integer(getCaid(chain[1])),
                        new SigningEntity(chain, keyFactory, providerName) );
            return true;
        }
        return false;
    }
    interface PrivateKeyFactory {
        PrivateKey getKey() throws Exception;
    }
    private class PrivateKeyFactorySW implements PrivateKeyFactory {
        final private PrivateKey privateKey;
        PrivateKeyFactorySW( PrivateKey key) {
            privateKey = key;
        }
        public PrivateKey getKey() throws Exception {
            return privateKey;
        }
    }
    private class PrivateKeyFactoryHW implements PrivateKeyFactory {
        final private RSAPublicKey publicKey;
        PrivateKeyFactoryHW( RSAPublicKey key) {
            publicKey = key;
        }
        public PrivateKey getKey() throws Exception {
            return mHardTokenObject.getPrivateKey(publicKey);
        }
    }
    private boolean putSignEntityHW( X509Certificate cert, Admin adm, String sFile ) {
        if ( cert!=null ) {
            try {
                PrivateKeyFactory keyFactory = new PrivateKeyFactoryHW((RSAPublicKey)cert.getPublicKey());
                if ( keyFactory!=null ) {
                    m_log.debug("HW key added. Cert from "+sFile+". DN: "+cert.getSubjectDN());
                    return putSignEntity( keyFactory, cert, adm, "PrimeKey" );
                }
            } catch( Exception e) {
                m_log.debug("Exception when fetching private key: ", e);
            }
            m_log.debug("Not possible to add HW key. Cert from "+sFile+". DN: "+cert.getSubjectDN());
        } else
            m_log.debug("File "+sFile+" has no cert.");
        return false;
    }
    private void loadFromKeyCards(Admin adm, String fileName) {
        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            throw new Error(e);
        }
        boolean isPEM = true;
        try {// read certs from PKCS#7 file
            final Collection c = cf.generateCertificates(new FileInputStream(fileName));
            if ( c!=null && !c.isEmpty() ) {
                Iterator i = c.iterator();
                while (i.hasNext())
                    isPEM = putSignEntityHW((X509Certificate)i.next(), adm, fileName+" PKCS#7");
            }
        } catch( Exception e) {
            m_log.debug(fileName+" is not a PKCS#7 file: "+e);
        }
        if ( !isPEM ) {
            // read concatinated cert in PEM format
            try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
            while (bis.available() > 0)
                putSignEntityHW((X509Certificate)cf.generateCertificate(bis), adm, fileName+" PEM");
            } catch( Exception e) {
                m_log.debug(fileName+" is not a PEM file: "+e);
            }
        }
    }
    protected void loadPrivateKeys(Admin adm) throws ServletException, IOException {
        mSignEntity.clear();
        File dir = new File(mKeystoreDirectoryName);
        if ( dir==null || dir.isDirectory()==false )
            throw new ServletException(dir.getCanonicalPath() + " is not a directory.");
        File files[] = dir.listFiles();
        if ( files==null || files.length==0 )
            throw new ServletException("No files in soft key directory: " + dir.getCanonicalPath());
        for ( int i=0; i<files.length; i++ ) {
            final String fileName = files[i].getCanonicalPath();
            if ( !loadFromKeyStore(adm, fileName) )
                loadFromKeyCards(adm, fileName);
        }
        if ( mSignEntity.size()==0 )
            throw new ServletException("No valid keys in directory " + dir.getCanonicalPath());
    }
    private class SigningEntity {
        final private X509Certificate mChain[];
        final private PrivateKeyFactory mKeyFactory;
        final private String providerName;
        SigningEntity(X509Certificate c[], PrivateKeyFactory f, String sName) {
            mChain = c;
            mKeyFactory = f;
            providerName = sName;
        }
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException {
            final BasicOCSPRespGenerator ocsprespgen = (request).getOCSPrespGenerator();
            final String sigAlg = (request).getSigAlg();
            m_log.debug("signing algorithm: "+sigAlg);
            final X509Certificate[] chain = (request).includeChain() ? mChain : null;
            try {
                final BasicOCSPResp ocspresp = ocsprespgen.generate(sigAlg, mKeyFactory.getKey(), chain, new Date(), providerName );
                m_log.debug("The OCSP response is "
                        + (ocspresp.verify(chain[0].getPublicKey(), "BC") ? "" : "NOT ") + "verifying.");
                return new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));             
            } catch (Exception e) {
                throw new ExtendedCAServiceRequestException(e);
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
