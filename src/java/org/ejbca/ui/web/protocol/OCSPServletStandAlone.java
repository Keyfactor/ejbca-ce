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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.ui.web.pub.cluster.ExtOCSPHealthCheck;
import org.ejbca.util.KeyTools;

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
 * @web.servlet-init-param description="The password for the all the soft keys of the OCSP responder."
 *   name="keyPassword"
 *   value="${ocsp.keys.keyPassword}"
 *
 * @web.servlet-init-param description="The password to all soft keystores."
 *   name="storePassword"
 *   value="${ocsp.keys.storePassword}"
 *
 * @web.servlet-init-param description="The password for all keys stored on card."
 *   name="cardPassword"
 *   value="${ocsp.keys.cardPassword}"
 *
 * @web.servlet-init-param description="The class that implements card signing of the OCSP response."
 *   name="hardTokenClassName"
 *   value="${ocsp.hardToken.className}"
 *
 * @web.servlet-init-param description="P11 shared library path name."
 *   name="sharedLibrary"
 *   value="${ocsp.p11.sharedLibrary}"
 *
 * @web.servlet-init-param description="P11 password."
 *   name="p11password"
 *   value="${ocsp.p11.p11password}"
 *
 * @web.servlet-init-param description="P11 slot number."
 *   name="slot"
 *   value="${ocsp.p11.slot}"
 *
 * @web.resource-ref
 *  name="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *  type="javax.sql.DataSource"
 *  auth="Container"
 *  
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreOnlyDataSessionLocal"
 *  type="Session"
 *  link="CertificateStoreOnlyDataSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal"
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public class OCSPServletStandAlone extends OCSPServletBase implements IHealtChecker {

    /**
     * 
     */
    private static final long serialVersionUID = -7093480682721604160L;
    static final private Logger m_log = Logger.getLogger(OCSPServletStandAlone.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private String mKeystoreDirectoryName;
    private String mKeyPassword;
    private String mStorePassword;
    private CardKeys mCardTokenObject;
	private final Map mSignEntity;
    private ICertificateStoreOnlyDataSessionLocal m_certStore = null;
    private String mSlot;
    private String mSharedLibrary;
    private String mP11Password;
    private boolean mIsIndex;

    public OCSPServletStandAlone() {
        super();
        mSignEntity = new HashMap();
    }
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            mSharedLibrary = config.getInitParameter("sharedLibrary");
            if ( mSharedLibrary!=null && mSharedLibrary.length()>0 ) {
                final String slot = config.getInitParameter("slot");
                final char firstChar = slot!=null && slot.length()>0 ? slot.charAt(0) : '\0';
                if ( firstChar=='i'||firstChar=='I' ) {
                    mSlot = slot.substring(1);
                    mIsIndex = true;
                } else {
                    mSlot = slot;
                    mIsIndex = false;
                }
                mP11Password = config.getInitParameter("p11password");
            } else
                mSlot = null;
            mKeyPassword = config.getInitParameter("keyPassword");
            if ( mKeyPassword==null || mKeyPassword.length()==0 )
                throw new ServletException("no keystore password given");
            mStorePassword = config.getInitParameter("storePassword");
            if ( mCardTokenObject==null ) {
                final String hardTokenClassName = config.getInitParameter("hardTokenClassName");
                if ( hardTokenClassName!=null && hardTokenClassName.length()>0 ) {
                    String sCardPassword = config.getInitParameter("cardPassword");
                    sCardPassword = sCardPassword!=null ? sCardPassword.trim() : null;
                    if ( sCardPassword!=null && sCardPassword.length()>0 ) {
                        try {
                            mCardTokenObject = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(hardTokenClassName).newInstance();
                            mCardTokenObject.autenticate(sCardPassword);
                        } catch( ClassNotFoundException e) {
                    		String iMsg = intres.getLocalizedMessage("ocsp.classnotfound", hardTokenClassName);
                            m_log.info(iMsg);
                        }
                    } else {
                		String iMsg = intres.getLocalizedMessage("ocsp.nocardpwd");
                        m_log.info(iMsg);
                    }
                } else {
            		String iMsg = intres.getLocalizedMessage("ocsp.nohwsigningclass");
            		m_log.info(iMsg);
                }
            }
            if ( mStorePassword==null || mStorePassword.length()==0 )
                mStorePassword = mKeyPassword;
            mKeystoreDirectoryName = config.getInitParameter("softKeyDirectoryName");
            if ( mKeystoreDirectoryName!=null && mKeystoreDirectoryName.length()>0 ) {
                ExtOCSPHealthCheck.setHealtChecker(this);
                return;
            } else {
        		String errMsg = intres.getLocalizedMessage("ocsp.errornovalidkeys");
            	throw new ServletException(errMsg);
            }
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorinitialize");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        }
    }
    
    /**
     * Returns the certificate data only session bean
     */
    private synchronized ICertificateStoreOnlyDataSessionLocal getStoreSessionOnlyData(){
    	if(m_certStore == null){	
    		try {
                ServiceLocator locator = ServiceLocator.getInstance();
                ICertificateStoreOnlyDataSessionLocalHome castorehome =
                    (ICertificateStoreOnlyDataSessionLocalHome)locator.getLocalHome(ICertificateStoreOnlyDataSessionLocalHome.COMP_NAME);
                m_certStore = castorehome.create();
    		}catch(Exception e){
    			throw new EJBException(e);      	  	    	  	
    		}
    	}
    	return m_certStore;
    }

    private X509Certificate[] getCertificateChain(X509Certificate cert, Admin adm) {
        RevokedCertInfo revokedInfo = isRevoked(adm, cert.getIssuerDN().getName(),
                cert.getSerialNumber());
		String wMsg = intres.getLocalizedMessage("ocsp.signcertnotindb", cert.getSerialNumber().toString(16), cert.getIssuerDN());
        if ( revokedInfo==null ) {
            m_log.warn(wMsg);
            return null;
        }
        if ( revokedInfo.getReason()!=RevokedCertInfo.NOT_REVOKED ) {
    		wMsg = intres.getLocalizedMessage("ocsp.signcertrevoked", cert.getSerialNumber().toString(16), cert.getIssuerDN());
            m_log.warn(wMsg);
            return null;
        }
        X509Certificate chain[] = null;
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
        		if (m_log.isDebugEnabled()) {
            		m_log.debug( "current issuer '" + current.getIssuerX500Principal() +
            				"'. target subject: '" + target.getSubjectX500Principal() + "'.");        			
        		}
        		if ( current.getIssuerX500Principal().equals(target.getSubjectX500Principal()) ) {
        			current = target;
        			isNotFound = false;
        		}
        	}
        	if ( isNotFound )
        		break;
        }
        if ( chain==null ) {
    		wMsg = intres.getLocalizedMessage("ocsp.signcerthasnochain", cert.getSerialNumber().toString(16), cert.getIssuerDN());
        	m_log.warn(wMsg);
        }
        return chain;
    }
    private boolean loadFromP11HSM(Admin adm) throws Exception {
        if ( mSharedLibrary==null || mSharedLibrary.length()<1 )
            return false;
        final Provider provider = KeyTools.getP11AuthProvider(mSlot, mSharedLibrary, mIsIndex);
        Security.addProvider( provider );

        final PasswordProtection pwp =new PasswordProtection( (mP11Password!=null && mP11Password.length()>0)? mStorePassword.toCharArray():null );
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider, pwp);
        final KeyStore keyStore = builder.getKeyStore();
        m_log.debug("Loading key from slot '"+mSlot+"' using pin.");
        keyStore.load(null, null);
        loadFromKeyStore(adm, keyStore, null, mSharedLibrary, provider.getName());
        pwp.destroy();
        return true;
    }
    private boolean loadFromSWKeyStore(Admin adm, String fileName) {
        try {
            KeyStore keyStore;
            try {
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(fileName), mStorePassword.toCharArray());
            } catch( IOException e ) {
                keyStore = KeyStore.getInstance("PKCS12", "BC");
                keyStore.load(new FileInputStream(fileName), mStorePassword.toCharArray());
            }
            loadFromKeyStore(adm, keyStore, mKeyPassword, fileName, "BC");
        } catch( Exception e ) {
            m_log.debug("Unable to load key file "+fileName+". Exception: "+e.getMessage());
            return false;
        }
        return true;
    }
    private boolean signTest(PrivateKey privateKey, PublicKey publicKey, String alias, String providerName) throws Exception {
        final String sigAlgName = "SHA1withRSA";
        final byte signInput[] = "Lillan gick på vägen ut.".getBytes();
        final byte signBA[];
        final boolean result;{
            Signature signature = Signature.getInstance(sigAlgName, providerName);
            signature.initSign( privateKey );
            signature.update( signInput );
            signBA = signature.sign();
        }
        {
            Signature signature = Signature.getInstance(sigAlgName);
            signature.initVerify(publicKey);
            signature.update(signInput);
            result = signature.verify(signBA);
            m_log.debug("Signature test of key "+alias+
                        ": signature length " + signBA.length +
                        "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                        "; verifying " + result);
        }
        return result;
    }
    private void loadFromKeyStore(Admin adm, KeyStore keyStore, String keyPassword,
                                  String errorComment, String providerName) throws KeyStoreException {
        final Enumeration eAlias = keyStore.aliases();
        while( eAlias.hasMoreElements() ) {
            final String alias = (String)eAlias.nextElement();
            try {
                final PrivateKey key = (PrivateKey)keyStore.getKey(alias, keyPassword!=null ? keyPassword.toCharArray() : null);
                final X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                
                if ( key!=null && cert!=null && signTest(key, cert.getPublicKey(), errorComment, providerName) ) {
                    putSignEntity(new PrivateKeyFactoryKeyStore(key), cert, adm, providerName);
                }
            } catch (Exception e) {
                String errMsg = intres.getLocalizedMessage("ocsp.errorgetalias", alias, errorComment);
                m_log.error(errMsg, e);
            }
        }
    }
    private boolean putSignEntity( PrivateKeyFactory keyFactory, X509Certificate cert, Admin adm, String providerName ) {
        if ( keyFactory==null || cert==null )
            return false;
        X509Certificate[] chain = getCertificateChain(cert, adm);
        if ( chain!=null ) {
            int caid = getCaid(chain[1]);
            m_log.debug("CA with ID "+caid+" now has a OCSP signing key.");
            SigningEntity oldSigningEntity = (SigningEntity)mSignEntity.get(new Integer(caid));
            if ( oldSigningEntity!=null && !oldSigningEntity.getCertificateChain().equals(chain) ) {
                String wMsg = intres.getLocalizedMessage("ocsp.newsigningkey", chain[1].getSubjectDN(), chain[0].getSubjectDN());
                m_log.warn(wMsg);
            }
            mSignEntity.put( new Integer(caid), new SigningEntity(chain, keyFactory, providerName) );
        }
        return true;
    }
    public String healtCheck() {
    	StringWriter sw = new StringWriter();
    	PrintWriter pw = new PrintWriter(sw);
        try {
			loadCertificates();
            Iterator i = mSignEntity.values().iterator();
	    	while ( i.hasNext() ) {
	    		SigningEntity signingEntity = (SigningEntity)i.next();
	    		if ( !signingEntity.isOK() ) {
                    pw.println();
            		String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", signingEntity.getCertificateChain()[1].getSubjectDN(), signingEntity.getCertificateChain()[0].getSerialNumber().toString(16));
	    			pw.print(errMsg);
	    			m_log.error(errMsg);
	    		}
	    	}
		} catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            m_log.error(errMsg, e);
			pw.print(errMsg + ": "+e.getMessage());
		}
    	pw.flush();
    	return sw.toString();
    }
    interface PrivateKeyFactory {
        PrivateKey getKey() throws Exception;

		boolean isOK();
    }
    private class PrivateKeyFactoryKeyStore implements PrivateKeyFactory {
        final private PrivateKey privateKey;
        PrivateKeyFactoryKeyStore( PrivateKey key) {
            privateKey = key;
        }
        public PrivateKey getKey() throws Exception {
            return privateKey;
        }
		public boolean isOK() {
			// SW checked when initialized
			return privateKey!=null;
		}
    }
    private class PrivateKeyFactoryCard implements PrivateKeyFactory {
        final private RSAPublicKey publicKey;
        PrivateKeyFactoryCard( RSAPublicKey key) {
            publicKey = key;
        }
        public PrivateKey getKey() throws Exception {
            return mCardTokenObject.getPrivateKey(publicKey);
        }
		public boolean isOK() {
			return mCardTokenObject.isOK(publicKey);
		}
    }
    private boolean putSignEntityCard( Object obj, Admin adm ) {
        if ( obj!=null && obj instanceof X509Certificate ) {
            X509Certificate cert = (X509Certificate)obj;
            PrivateKeyFactory keyFactory = new PrivateKeyFactoryCard((RSAPublicKey)cert.getPublicKey());
            putSignEntity( keyFactory, cert, adm, "PrimeKey" );
            m_log.debug("HW key added. Serial number: "+cert.getSerialNumber().toString(0x10));
            return true;
        } else
            return false;
    }
    private void loadFromKeyCards(Admin adm, String fileName) {
        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            throw new Error(e);
        }
        String fileType = null;
        try {// read certs from PKCS#7 file
            final Collection c = cf.generateCertificates(new FileInputStream(fileName));
            if ( c!=null && !c.isEmpty() ) {
                Iterator i = c.iterator();
                while (i.hasNext()) {
                    if ( putSignEntityCard(i.next(), adm) )
                        fileType = "PKCS#7";
                }
            }
        } catch( Exception e) {
        }
        if ( fileType==null ) {
            try {// read concatinated cert in PEM format
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
                while (bis.available() > 0) {
                    if ( putSignEntityCard(cf.generateCertificate(bis), adm) )
                        fileType="PEM";
                }
            } catch(Exception e){
            }
        }
        if ( fileType!=null )
            m_log.debug("Certificate(s) found in file "+fileName+" of "+fileType+".");
        else
            m_log.debug("File "+fileName+" has no cert.");
    }
    protected void loadPrivateKeys(Admin adm) throws Exception {
        mSignEntity.clear();
        loadFromP11HSM(adm);
        File dir = new File(mKeystoreDirectoryName);
        if ( dir==null || dir.isDirectory()==false )
            throw new ServletException(dir.getCanonicalPath() + " is not a directory.");
        File files[] = dir.listFiles();
        if ( files==null || files.length==0 )
            throw new ServletException("No files in soft key directory: " + dir.getCanonicalPath());
        for ( int i=0; i<files.length; i++ ) {
            final String fileName = files[i].getCanonicalPath();
            if ( !loadFromSWKeyStore(adm, fileName) )
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
        	X509Certificate signerCert = mChain[0];
            final String sigAlgs = request.getSigAlg();
        	PublicKey pk = signerCert.getPublicKey();
            String sigAlg = OCSPUtil.getSigningAlgFromAlgSelection(sigAlgs, pk);
            m_log.debug("Signing algorithm: "+sigAlg);
            final X509Certificate[] chain = request.includeChain() ? mChain : null;
            try {
                BasicOCSPResp ocspresp = OCSPUtil.generateBasicOCSPResp(request, sigAlg, signerCert, mKeyFactory.getKey(), providerName, chain);
                return new OCSPCAServiceResponse(ocspresp, chain == null ? null : Arrays.asList(chain));             
            } catch (Exception e) {
                throw new ExtendedCAServiceRequestException(e);
            }
        }
        boolean isOK() {
        	try {
				return mKeyFactory.isOK();
			} catch (Exception e) {
				m_log.info("Exception thrown when accessing the private key: ", e);
				return false;
			}
        }
        X509Certificate[] getCertificateChain() {
        	return mChain;
        }
    }

    protected Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
        return getStoreSessionOnlyData().findCertificatesByType(adm, type, issuerDN);
    }

    protected Certificate findCertificateByIssuerAndSerno(Admin adm, String issuer, BigInteger serno) {
        return getStoreSessionOnlyData().findCertificateByIssuerAndSerno(adm, issuer, serno);
    }
    
    protected OCSPCAServiceResponse extendedService(Admin adm, int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException,
                                                                                                    ExtendedCAServiceNotActiveException {
        SigningEntity se =(SigningEntity)mSignEntity.get(new Integer(caid));
        if ( se!=null ) {
            return se.sign(request);            
        }
        throw new ExtendedCAServiceNotActiveException("No ocsp signing key for caid "+caid);
    }

    protected RevokedCertInfo isRevoked(Admin adm, String name, BigInteger serialNumber) {
        return getStoreSessionOnlyData().isRevoked(adm, name, serialNumber);
    }
}
