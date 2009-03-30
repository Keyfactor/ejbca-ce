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
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.CertificateCache;
import org.ejbca.core.protocol.ocsp.CertificateCacheStandalone;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.ui.web.pub.cluster.ExtOCSPHealthCheck;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.P11Slot;
import org.ejbca.util.keystore.P11Slot.P11SlotUser;

/** 
  *
 * @author Lars Silven PrimeKey
 * @version  $Id
 */
class OCSPServletStandAloneSession implements P11SlotUser {

    static final private Logger m_log = Logger.getLogger(OCSPServletStandAloneSession.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    final private String mKeystoreDirectoryName;
    final private String mKeyPassword;
    final private String mStorePassword;
    final private CardKeys mCardTokenObject;
	final private Map<Integer, SigningEntity> signEntity;
	final private Map<Integer, SigningEntity> newSignEntity;
    final private P11Slot slot;
    final private String mP11Password;
    final private OCSPServletStandAlone servlet;
    private boolean isActive;

    OCSPServletStandAloneSession(ServletConfig config,
                                 OCSPServletStandAlone _servlet) throws ServletException {
        this.signEntity = new ConcurrentHashMap<Integer, SigningEntity>();
        this.newSignEntity = new HashMap<Integer, SigningEntity>();
        this.isActive = false;
        this.servlet = _servlet;
        try {
            final boolean isIndex;
            final String sharedLibrary = config.getInitParameter("sharedLibrary");
            if ( sharedLibrary!=null && sharedLibrary.length()>0 ) {
                final String sSlot;
                final String sSlotRead = config.getInitParameter("slot");
                if ( sSlotRead==null || sSlotRead.length()<1 ) {
                    throw new ServletException("No slot number given.");
                }
                final char firstChar = sSlotRead.charAt(0);
                if ( firstChar=='i'||firstChar=='I' ) {
                    sSlot = sSlotRead.substring(1).trim();
                    isIndex = true;
                } else {
                    sSlot = sSlotRead.trim();
                    isIndex = false;
                }
                this.slot = P11Slot.getInstance(sSlot, sharedLibrary, isIndex, null, this);
    			m_log.debug("sharedLibrary is: "+sharedLibrary);
            } else {
            	this.slot = null;
            	m_log.debug("No shared P11 library.");
            }
            this.mP11Password = config.getInitParameter("p11password");
			this.mKeyPassword = config.getInitParameter("keyPassword");
			if ( this.mKeyPassword==null || this.mKeyPassword.length()==0 ) {
			    throw new ServletException("no keystore password given");
			}
			final String hardTokenClassName = config.getInitParameter("hardTokenClassName");
			if ( hardTokenClassName!=null && hardTokenClassName.length()>0 ) {
			    String sCardPassword = config.getInitParameter("cardPassword");
			    sCardPassword = sCardPassword!=null ? sCardPassword.trim() : null;
                CardKeys tmp = null;
			    if ( sCardPassword!=null && sCardPassword.length()>0 ) {
			        try {
			            tmp = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(hardTokenClassName).newInstance();
			            tmp.autenticate(sCardPassword);
			        } catch( ClassNotFoundException e) {
			            String iMsg = intres.getLocalizedMessage("ocsp.classnotfound", hardTokenClassName);
			            m_log.info(iMsg);
			        }
			    } else {
			        String iMsg = intres.getLocalizedMessage("ocsp.nocardpwd");
			        m_log.info(iMsg);
			    }
                this.mCardTokenObject = tmp;
			} else {
                this.mCardTokenObject = null;
			    String iMsg = intres.getLocalizedMessage("ocsp.nohwsigningclass");
			    m_log.info(iMsg);
			}
			{
			    final String sTmp = config.getInitParameter("storePassword");
			    if ( sTmp==null || sTmp.length()==0 ) {
			        this.mStorePassword = this.mKeyPassword;
			    } else {
			        this.mStorePassword = sTmp;
			    }
			}            
            this.mKeystoreDirectoryName = config.getInitParameter("softKeyDirectoryName");
            m_log.debug("softKeyDirectoryName is: "+this.mKeystoreDirectoryName);
            if ( this.mKeystoreDirectoryName!=null && this.mKeystoreDirectoryName.length()>0 ) {
                ExtOCSPHealthCheck.setHealtChecker(this.servlet);
            } else {
        		String errMsg = intres.getLocalizedMessage("ocsp.errornovalidkeys");
            	throw new ServletException(errMsg);
            }
            
    		// Load OCSP responders private keys into cache in init to speed things up for the first request
            loadPrivateKeys(this.servlet.m_adm);	
            
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
    		String errMsg = intres.getLocalizedMessage("ocsp.errorinitialize");
            m_log.error(errMsg, e);
            throw new ServletException(e);
        }
        this.isActive = true;
    }
    
    private X509Certificate[] getCertificateChain(X509Certificate cert, Admin adm) {
    	String issuerDN = CertTools.getIssuerDN(cert);
        final CertificateStatus status = this.servlet.getStatus(adm, issuerDN, CertTools.getSerialNumber(cert));
        if ( status.equals(CertificateStatus.NOT_AVAILABLE) ) {
    		String wMsg = intres.getLocalizedMessage("ocsp.signcertnotindb", CertTools.getSerialNumberAsString(cert), issuerDN);
            m_log.warn(wMsg);
            return null;
        }
        if ( status.equals(CertificateStatus.REVOKED) ) {
    		String wMsg = intres.getLocalizedMessage("ocsp.signcertrevoked", CertTools.getSerialNumberAsString(cert), issuerDN);
            m_log.warn(wMsg);
            return null;
        }
        X509Certificate chain[] = null;
        final List<X509Certificate> list = new ArrayList<X509Certificate>();
        X509Certificate current = cert;
        while( true ) {
        	list.add(current);
        	if ( CertTools.isSelfSigned(current) ) {
        		chain = list.toArray(new X509Certificate[0]);
        		break;
        	}
        	// Is there a CA certificate?
        	X509Certificate target = this.servlet.m_caCertCache.findLatestBySubjectDN(CertTools.getIssuerDN(current));
        	if (target != null) {
    			current = target;
        	} else {
        		break;        		
        	}
        }
        if ( chain==null ) {
    		String wMsg = intres.getLocalizedMessage("ocsp.signcerthasnochain", CertTools.getSerialNumberAsString(cert), issuerDN);
        	m_log.warn(wMsg);
        }
        return chain;
    }
    private boolean loadFromP11HSM(Admin adm) throws Exception {
    	m_log.trace(">loadFromP11HSM");
        if ( this.slot==null ) {
        	m_log.trace("<loadFromP11HSM: no shared library");
            return false;        	
        }
        final P11ProviderHandler providerHandler = new P11ProviderHandler();
        final PasswordProtection pwp = providerHandler.getPwd();
        loadFromKeyStore(adm, providerHandler.getKeyStore(pwp), null, this.slot.toString(), providerHandler);
        pwp.destroy();
    	m_log.trace("<loadFromP11HSM");
        return true;
    }
    private boolean loadFromSWKeyStore(Admin adm, String fileName) {
    	m_log.trace(">loadFromSWKeyStore");
    	boolean ret = false;
        try {
            KeyStore keyStore;
            try {
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(fileName), this.mStorePassword.toCharArray());
            } catch( IOException e ) {
                keyStore = KeyStore.getInstance("PKCS12", "BC");
                keyStore.load(new FileInputStream(fileName), this.mStorePassword.toCharArray());
            }
            loadFromKeyStore(adm, keyStore, this.mKeyPassword, fileName, new SWProviderHandler());
            ret = true;
        } catch( Exception e ) {
            m_log.debug("Unable to load key file "+fileName+". Exception: "+e.getMessage());
        }
    	m_log.trace("<loadFromSWKeyStore");
        return ret;
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
                                  String errorComment, ProviderHandler providerHandler) throws KeyStoreException {
        final Enumeration<String> eAlias = keyStore.aliases();
        while( eAlias.hasMoreElements() ) {
            final String alias = eAlias.nextElement();
            try {
                final X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Trying to load signing keys for signer with subjectDN (EJBCA ordering) '"+CertTools.getSubjectDN(cert)+"', keystore alias '"+alias+"'");                	
                }
                final PrivateKeyFactory pkf = new PrivateKeyFactoryKeyStore(alias, keyPassword!=null ? keyPassword.toCharArray() : null, keyStore);
                if ( pkf.getKey()!=null && cert!=null && signTest(pkf.getKey(), cert.getPublicKey(), errorComment, providerHandler.getProviderName()) ) {
                    putSignEntity(pkf, cert, adm, providerHandler);
                } else {
                    if (m_log.isDebugEnabled()) {
                    	m_log.debug("Not adding a signEntity for: "+CertTools.getSubjectDN(cert));
                    }
                }
            } catch (Exception e) {
                String errMsg = intres.getLocalizedMessage("ocsp.errorgetalias", alias, errorComment);
                m_log.error(errMsg, e);
            }
        }
    }
    private boolean putSignEntity( PrivateKeyFactory keyFactory, X509Certificate cert, Admin adm, ProviderHandler providerHandler ) {
        if ( keyFactory==null || cert==null )
            return false;
        providerHandler.addKeyFactory(keyFactory);
        final X509Certificate[] chain = getCertificateChain(cert, adm);
        if ( chain!=null ) {
            final int caid = this.servlet.getCaid(chain[1]);
            final SigningEntity oldSigningEntity = this.signEntity.get(new Integer(caid));
            if ( oldSigningEntity!=null && !CertTools.compareCertificateChains(oldSigningEntity.getCertificateChain(), chain) ) {
                final String wMsg = intres.getLocalizedMessage("ocsp.newsigningkey", chain[1].getSubjectDN(), chain[0].getSubjectDN());
                m_log.warn(wMsg);
            }
            this.newSignEntity.put( new Integer(caid), new SigningEntity(chain, keyFactory, providerHandler) );
            m_log.debug("CA with ID "+caid+" now has a OCSP signing key.");
        }
        return true;
    }
    String healthCheck() {
    	StringWriter sw = new StringWriter();
    	PrintWriter pw = new PrintWriter(sw);
        try {
        	loadPrivateKeys(this.servlet.m_adm);
            Iterator<SigningEntity> i = this.signEntity.values().iterator();
	    	while ( i.hasNext() ) {
	    		SigningEntity signingEntity = i.next();
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
    private interface PrivateKeyFactory {
        /**
         * @return the key
         * @throws Exception
         */
        PrivateKey getKey() throws Exception;
        /**
         * @param keyStore sets key from keystore
         * @throws Exception
         */
        void set(KeyStore keyStore) throws Exception;
        /**
         * removes key
         */
        void clear();
		/**
		 * @return is key OK to use.
		 */
		boolean isOK();
    }
    private class PrivateKeyFactoryKeyStore implements PrivateKeyFactory {
        final private char password[];
        final private String alias;
        private PrivateKey privateKey;
        PrivateKeyFactoryKeyStore( String a, char pw[], KeyStore keyStore) throws Exception {
            this.alias = a;
            this.password = pw;
            set(keyStore);
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#set(java.security.KeyStore)
         */
        public void set(KeyStore keyStore) throws Exception {
            this.privateKey = keyStore!=null ? (PrivateKey)keyStore.getKey(this.alias, this.password) : null;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#clear()
         */
        public void clear() {
            this.privateKey = null;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#getKey()
         */
        public PrivateKey getKey() throws Exception {
            return this.privateKey;
        }
		/* (non-Javadoc)
		 * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#isOK()
		 */
		public boolean isOK() {
			// SW checked when initialized
			return this.privateKey!=null;
		}
        /* (non-Javadoc)
         * @see java.lang.Object#toString()
         */
        @Override
        public String toString() {
            return "PrivateKeyFactoryKeyStore for key with alias "+this.alias+'.';
        }
    }
    private class PrivateKeyFactoryCard implements PrivateKeyFactory {
        final private RSAPublicKey publicKey;
        PrivateKeyFactoryCard( RSAPublicKey key) {
            this.publicKey = key;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#getKey()
         */
        public PrivateKey getKey() throws Exception {
            return OCSPServletStandAloneSession.this.mCardTokenObject.getPrivateKey(this.publicKey);
        }
		/* (non-Javadoc)
		 * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#isOK()
		 */
		public boolean isOK() {
			return OCSPServletStandAloneSession.this.mCardTokenObject.isOK(this.publicKey);
		}
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#clear()
         */
        public void clear() {
            // not used by cards.
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory#set(java.security.KeyStore)
         */
        public void set(KeyStore keyStore) throws Exception {
            // not used by cards.
        }
    }
    private boolean putSignEntityCard( Certificate _cert, Admin adm ) {
        if ( _cert!=null &&  _cert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate)_cert;
            final PrivateKeyFactory keyFactory = new PrivateKeyFactoryCard((RSAPublicKey)cert.getPublicKey());
            putSignEntity( keyFactory, cert, adm, new CardProviderHandler() );
            m_log.debug("HW key added. Serial number: "+cert.getSerialNumber().toString(0x10));
            return true;
        }
        return false;
    }
    private void loadFromKeyCards(Admin adm, String fileName) {
    	m_log.trace(">loadFromKeyCards");
        final CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            throw new Error(e);
        }
        String fileType = null;
        try {// read certs from PKCS#7 file
            final Collection<? extends Certificate> c = cf.generateCertificates(new FileInputStream(fileName));
            if ( c!=null && !c.isEmpty() ) {
                Iterator<? extends Certificate> i = c.iterator();
                while (i.hasNext()) {
                    if ( putSignEntityCard(i.next(), adm) )
                        fileType = "PKCS#7";
                }
            }
        } catch( Exception e) {
            // do nothing
        }
        if ( fileType==null ) {
            try {// read concatenated certificate in PEM format
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
                while (bis.available() > 0) {
                    if ( putSignEntityCard(cf.generateCertificate(bis), adm) )
                        fileType="PEM";
                }
            } catch(Exception e){
                // do nothing
            }
        }
        if ( fileType!=null ) {
            m_log.debug("Certificate(s) found in file "+fileName+" of "+fileType+".");
        } else {
            m_log.debug("File "+fileName+" has no cert.");
        }
    	m_log.trace("<loadFromKeyCards");
    }
    void loadPrivateKeys(Admin adm) throws Exception {
    	m_log.trace(">loadPrivateKeys");
    	// We will only load private keys if the cache time has run out
		if ( (this.signEntity != null) && (this.signEntity.size() > 0) && (this.servlet.mKeysValidTo > new Date().getTime()) ) {
	    	m_log.trace("<loadPrivateKeys: using cache");
			return;
		}
        this.newSignEntity.clear();
        loadFromP11HSM(adm);
        final File dir = this.mKeystoreDirectoryName!=null ? new File(this.mKeystoreDirectoryName) : null;
        if ( dir!=null && dir.isDirectory() ) {
            final File files[] = dir.listFiles();
            if ( files!=null && files.length>0 ) {
                for ( int i=0; i<files.length; i++ ) {
                    final String fileName = files[i].getCanonicalPath();
                    if ( !loadFromSWKeyStore(adm, fileName) )
                        loadFromKeyCards(adm, fileName);
                }
            } else {
            	m_log.debug("No files in directory: " + dir.getCanonicalPath());            	
                if ( this.newSignEntity.size()<1 ) {
                    throw new ServletException("No files in soft key directory: " + dir.getCanonicalPath());            	
                }
            }
        } else {
        	m_log.debug((dir != null ? dir.getCanonicalPath() : "null") + " is not a directory.");
            if ( this.newSignEntity.size()<1 ) {
                throw new ServletException((dir != null ? dir.getCanonicalPath() : "null") + " is not a directory.");
            }
        }
        // No P11 keys, there are files, but none are valid keys or certs for cards
        if ( this.newSignEntity.size()<1 ) {
        	String dirStr = (dir != null ? dir.getCanonicalPath() : "null");
            throw new ServletException("No valid keys in directory " + dirStr+", or in PKCS#11 keystore.");        	
        }
        // Replace old signEntity references with new ones or null if they no longer exist
        Iterator<Integer> iterator = signEntity.keySet().iterator();
        while (iterator.hasNext()) {
        	Integer key = iterator.next();
        	if (newSignEntity.get(key) != null) {
            	signEntity.put(key, newSignEntity.get(key));
        	} else {
        		signEntity.remove(key);
        	}
        }
        // Replace existing signEntity references and add new ones. (Yes, we have some overlap here..)
        iterator = newSignEntity.keySet().iterator();
        while (iterator.hasNext()) {
        	Integer key = iterator.next();
        	signEntity.put(key, newSignEntity.get(key));
        }

        m_log.debug("We have keys, returning");
        
        // Update cache time
    	// If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
        this.servlet.mKeysValidTo = this.servlet.m_valid_time>0 ? new Date().getTime()+this.servlet.m_valid_time : Long.MAX_VALUE;
    	m_log.trace("<loadPrivateKeys");
    }
    
    private interface ProviderHandler {
        /**
         * @return name of the provider if an provider is available otherwise null
         */
        String getProviderName();
        /**
         * @param keyFactory to be updated at reload
         */
        void addKeyFactory(PrivateKeyFactory keyFactory);
        /**
         * start a threads that tryes to reload the provider until it is none
         */
        void reload();
    }
    private class CardProviderHandler implements ProviderHandler {
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#getProviderName()
         */
        public String getProviderName() {
            return "PrimeKey";
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#reload()
         */
        public void reload() {
            // not needed to reload.
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#addKeyFactory(org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory)
         */
        public void addKeyFactory(PrivateKeyFactory keyFactory) {
            // do nothing
        }
    }
    private class SWProviderHandler implements ProviderHandler {
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#getProviderName()
         */
        public String getProviderName() {
            return "BC";
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#reload()
         */
        public void reload() {
            // no use reloading a SW provider
        }
        public void addKeyFactory(PrivateKeyFactory keyFactory) {
            // do nothing
            
        }
    }
    private class P11ProviderHandler implements ProviderHandler {
        private String name;
        private boolean isOK;
        final Set<PrivateKeyFactory> sKeyFacrory = new HashSet<PrivateKeyFactory>();
        P11ProviderHandler() throws Exception {
            addProvider();
            this.isOK = true;
        }
        private void addProvider() throws Exception {
            Security.addProvider( OCSPServletStandAloneSession.this.slot.getProvider() );
            this.name = OCSPServletStandAloneSession.this.slot.getProvider().getName();
        }
        public KeyStore getKeyStore(PasswordProtection pwp) throws Exception {
            final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                                                                          OCSPServletStandAloneSession.this.slot.getProvider(),
                                                                          pwp);
            final KeyStore keyStore = builder.getKeyStore();
            m_log.debug("Loading key from slot '"+OCSPServletStandAloneSession.this.slot+"' using pin.");
            keyStore.load(null, null);
            return keyStore;
        }
        public PasswordProtection getPwd() {
            return new PasswordProtection( (OCSPServletStandAloneSession.this.mP11Password!=null && OCSPServletStandAloneSession.this.mP11Password.length()>0)? OCSPServletStandAloneSession.this.mP11Password.toCharArray():null );
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#getProviderName()
         */
        public String getProviderName() {
            return this.isOK ? this.name : null;
        }
        private class Reloader implements Runnable {
            public void run() {
                String errorMessage ="";
                while ( true ) try {
                    errorMessage = "";
                    {
                        final Iterator<PrivateKeyFactory> i = P11ProviderHandler.this.sKeyFacrory.iterator();
                        while ( i.hasNext() ) {
                            i.next().clear();
                        }
                    }
                    OCSPServletStandAloneSession.this.slot.reset();
                    OCSPServletStandAloneSession.this.isActive = true;
                    {
                        final Iterator<PrivateKeyFactory> i = P11ProviderHandler.this.sKeyFacrory.iterator();
                        while ( i.hasNext() ) {
                            PrivateKeyFactory pkf = i.next();
                            errorMessage = pkf.toString();
                            pkf.set(P11ProviderHandler.this.getKeyStore(P11ProviderHandler.this.getPwd()));
                        }
                    }
                    P11ProviderHandler.this.isOK = true;
                    return;
                } catch ( Throwable t ) {
                    m_log.debug("Failing to reload p11 keystore. "+errorMessage, t);
                }
            }
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#reload()
         */
        public synchronized void reload() {
            if ( !this.isOK )
                return;
            this.isOK = false;
            new Thread(new Reloader()).start();
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAlone.ProviderHandler#addKeyFactory(org.ejbca.ui.web.protocol.OCSPServletStandAlone.PrivateKeyFactory)
         */
        public void addKeyFactory(PrivateKeyFactory keyFactory) {
            this.sKeyFacrory.add(keyFactory);
        }
    }
    private class SigningEntity {
        final private X509Certificate mChain[];
        final private PrivateKeyFactory mKeyFactory;
        final private ProviderHandler providerHandler;
        SigningEntity(X509Certificate c[], PrivateKeyFactory f, ProviderHandler ph) {
            this.mChain = c;
            this.mKeyFactory = f;
            this.providerHandler = ph;
        }
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
        	PrivateKey privKey;
            final String hsmErrorString = "HSM not functional";
			try {
				privKey = this.mKeyFactory.getKey();
                if ( privKey==null )
                    throw new ExtendedCAServiceRequestException(hsmErrorString);
            } catch (ExtendedCAServiceRequestException e) {
                this.providerHandler.reload();
                throw e;
            } catch (Exception e) {
                throw new ExtendedCAServiceRequestException(e);
            }
        	if ( this.providerHandler.getProviderName()==null )
                throw new ExtendedCAServiceRequestException(hsmErrorString);
            try {
                return OCSPUtil.createOCSPCAServiceResponse(request, privKey, this.providerHandler.getProviderName(), this.mChain);
            } catch( ExtendedCAServiceRequestException e) {
                this.providerHandler.reload();
                throw e;
            } catch( IllegalExtendedCAServiceRequestException e ) {
                throw e;
            } catch( Throwable e ) {
                this.providerHandler.reload();
                final ExtendedCAServiceRequestException e1 = new ExtendedCAServiceRequestException(hsmErrorString);
                e1.initCause(e);
                throw e1;
            }
        }
        boolean isOK() {
        	try {
				return this.mKeyFactory.isOK();
			} catch (Exception e) {
				m_log.info("Exception thrown when accessing the private key: ", e);
				return false;
			}
        }
        X509Certificate[] getCertificateChain() {
        	return this.mChain;
        }
    }
    Certificate findCertificateByIssuerAndSerno(Admin adm, String issuer, BigInteger serno) {
        return this.servlet.getStoreSessionOnlyData().findCertificateByIssuerAndSerno(adm, issuer, serno);
    }
    OCSPCAServiceResponse extendedService(int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        SigningEntity se = this.signEntity.get(new Integer(caid));
        if ( se==null ) {
        	if (m_log.isDebugEnabled()) {
            	m_log.debug("No key is available for caid=" + caid + " even though a valid certificate was present. Trying to use the default responder's key instead.");
        	}
        	se = this.signEntity.get(new Integer(this.servlet.getCaid(null)));	// Use the key issued by the default responder ID instead
        }
        if ( se!=null ) {
            return se.sign(request);            
        }
        throw new ExtendedCAServiceNotActiveException("No ocsp signing key for caid "+caid);
    }
    CertificateCache createCertificateCache(Properties prop) {
		return new CertificateCacheStandalone(prop);
	}
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#deactivate()
     */
    public boolean deactivate() throws Exception {
        this.isActive = false;
        this.slot.removeProviderIfNoTokensActive();
        // should allways be active
        return true;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#isActive()
     */
    public boolean isActive() {
        // is allways active
        return this.isActive;
    }
}
