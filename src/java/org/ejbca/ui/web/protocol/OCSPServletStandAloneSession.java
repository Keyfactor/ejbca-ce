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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
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

import javax.servlet.ServletException;

import org.apache.log4j.Logger;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ocsp.CertificateCache;
import org.ejbca.core.protocol.ocsp.CertificateCacheStandalone;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
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

    final private String mKeystoreDirectoryName = OcspConfiguration.getSoftKeyDirectoryName();
    final private String mKeyPassword = OcspConfiguration.getKeyPassword();
    final private String mStorePassword = OcspConfiguration.getStorePassword();
    final private CardKeys mCardTokenObject;
	private Map<Integer, SigningEntity> signEntity;
    final private P11Slot slot;
    final private String mP11Password = OcspConfiguration.getP11Password();
    final private OCSPServletStandAlone servlet;

    /**
     * Called when a servlet is initialized. This should only occur once.
     * 
     * @param _servlet The servlet object.
     * @throws ServletException
     */
    OCSPServletStandAloneSession(OCSPServletStandAlone _servlet) throws ServletException {
        this.servlet = _servlet;
        try {
            final boolean isIndex;
            final String sharedLibrary = OcspConfiguration.getSharedLibrary();
            if ( sharedLibrary.length()>0 ) {
                final String sSlot;
                final String sSlotRead = OcspConfiguration.getSlot();
                if ( sSlotRead.length()<1 ) {
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
			if ( this.mKeyPassword.length()==0 ) {
			    throw new ServletException("no keystore password given");
			}
			final String hardTokenClassName = OcspConfiguration.getHardTokenClassName();
			if ( hardTokenClassName.length()>0 ) {
			    String sCardPassword = OcspConfiguration.getCardPassword();
			    sCardPassword = sCardPassword!=null ? sCardPassword.trim() : null;
                CardKeys tmp = null;
			    if ( sCardPassword!=null && sCardPassword.length()>0 ) {
			        try {
			            tmp = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(hardTokenClassName).newInstance();
			            tmp.autenticate(sCardPassword);
			        } catch( ClassNotFoundException e) {
			            m_log.info(intres.getLocalizedMessage("ocsp.classnotfound", hardTokenClassName));
			        }
			    } else {
			        m_log.info(intres.getLocalizedMessage("ocsp.nocardpwd"));
			    }
                this.mCardTokenObject = tmp;
			} else {
                this.mCardTokenObject = null;
                m_log.info( intres.getLocalizedMessage("ocsp.nohwsigningclass") );
			}
            m_log.debug("softKeyDirectoryName is: "+this.mKeystoreDirectoryName);
            if ( this.mKeystoreDirectoryName==null || this.mKeystoreDirectoryName.length()<1 ) {
            	throw new ServletException(intres.getLocalizedMessage("ocsp.errornovalidkeys"));
            }
    		// Load OCSP responders private keys into cache in init to speed things up for the first request
            // signEntity is also set
            loadPrivateKeys(this.servlet.m_adm);
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
            throw new ServletException(e);
        }
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
    private boolean loadFromP11HSM(Admin adm, HashMap<Integer, SigningEntity> newSignEntity) throws Exception {
    	m_log.trace(">loadFromP11HSM");
        if ( this.slot==null ) {
        	m_log.trace("<loadFromP11HSM: no shared library");
            return false;        	
        }
        this.slot.reset();
        final P11ProviderHandler providerHandler = new P11ProviderHandler();
        final PasswordProtection pwp = providerHandler.getPwd();
        loadFromKeyStore(adm, providerHandler.getKeyStore(pwp), null, this.slot.toString(), providerHandler, newSignEntity);
        pwp.destroy();
    	m_log.trace("<loadFromP11HSM");
        return true;
    }
    private boolean loadFromSWKeyStore(Admin adm, String fileName, HashMap<Integer, SigningEntity> newSignEntity) {
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
            loadFromKeyStore(adm, keyStore, this.mKeyPassword, fileName, new SWProviderHandler(), newSignEntity);
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
                                  String errorComment, ProviderHandler providerHandler,
                                  HashMap<Integer, SigningEntity> newSignEntity) throws KeyStoreException {
        final Enumeration<String> eAlias = keyStore.aliases();
        while( eAlias.hasMoreElements() ) {
            final String alias = eAlias.nextElement();
            try {
                final X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                if (m_log.isDebugEnabled()) {
                    m_log.debug("Trying to load signing keys for signer with subjectDN (EJBCA ordering) '"+CertTools.getSubjectDN(cert)+"', keystore alias '"+alias+"'");                	
                }
                final PrivateKeyContainer pkf = new PrivateKeyContainerKeyStore(alias, keyPassword!=null ? keyPassword.toCharArray() : null, keyStore);
                if ( pkf.getKey()!=null && cert!=null && signTest(pkf.getKey(), cert.getPublicKey(), errorComment, providerHandler.getProviderName()) ) {
                    putSignEntity(pkf, cert, adm, providerHandler, newSignEntity);
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
    private boolean putSignEntity( PrivateKeyContainer keyFactory, X509Certificate cert, Admin adm, ProviderHandler providerHandler,
                                   final Map<Integer, SigningEntity> newSignEntity) {
        if ( keyFactory==null || cert==null )
            return false;
        providerHandler.addKeyFactory(keyFactory);
        final X509Certificate[] chain = getCertificateChain(cert, adm);
        if ( chain==null ) {
            return false;
        }
        final Integer caid = new Integer(this.servlet.getCaid(chain[1]));
        {
            SigningEntity entityForSameCA = newSignEntity.get(caid);
            if ( entityForSameCA!=null && entityForSameCA.mChain[0].getNotBefore().after(cert.getNotBefore())) {
                m_log.debug("CA with ID "+caid+" has duplicated keys. Certificate for older key that is not used has serial number: "+cert.getSerialNumber().toString(0x10));
                return true; // the entity allready in the map is newer.
            }
        }{
            final SigningEntity oldSigningEntity = this.signEntity!=null ? this.signEntity.get(caid) : null;
            if ( oldSigningEntity!=null && !CertTools.compareCertificateChains(oldSigningEntity.getCertificateChain(), chain) ) {
                m_log.warn(intres.getLocalizedMessage("ocsp.newsigningkey", chain[1].getSubjectDN(), chain[0].getSubjectDN()));
            }
        }
        newSignEntity.put( caid, new SigningEntity(chain, keyFactory, providerHandler) );
        m_log.debug("CA with ID "+caid+" now has a OCSP signing key. Certificate with serial number: "+cert.getSerialNumber().toString(0x10));
        return true;
    }
    String healthCheck() {
    	StringWriter sw = new StringWriter();
    	PrintWriter pw = new PrintWriter(sw);
        try {
        	loadPrivateKeys(this.servlet.m_adm);
            final Iterator<SigningEntity> i = this.signEntity.values().iterator();
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
    private interface PrivateKeyContainer {
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
    private class PrivateKeyContainerKeyStore implements PrivateKeyContainer {
        final private char password[];
        final private String alias;
        private PrivateKey privateKey;
        PrivateKeyContainerKeyStore( String a, char pw[], KeyStore keyStore) throws Exception {
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
            return "PrivateKeyContainerKeyStore for key with alias "+this.alias+'.';
        }
    }
    private class PrivateKeyContainerCard implements PrivateKeyContainer {
        final private RSAPublicKey publicKey;
        PrivateKeyContainerCard( RSAPublicKey key) {
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
    private boolean putSignEntityCard( Certificate _cert, Admin adm,
                                       HashMap<Integer, SigningEntity> newSignEntity) {
        if ( _cert!=null &&  _cert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate)_cert;
            final PrivateKeyContainer keyFactory = new PrivateKeyContainerCard((RSAPublicKey)cert.getPublicKey());
            return putSignEntity( keyFactory, cert, adm, new CardProviderHandler(), newSignEntity );
        }
        return false;
    }
    private void loadFromKeyCards(Admin adm, String fileName, HashMap<Integer, SigningEntity> newSignEntity) {
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
                    if ( putSignEntityCard(i.next(), adm, newSignEntity) ) {
                        fileType = "PKCS#7";
                    }
                }
            }
        } catch( Exception e) {
            // do nothing
        }
        if ( fileType==null ) {
            try {// read concatenated certificate in PEM format
                final BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
                while (bis.available() > 0) {
                    if ( putSignEntityCard(cf.generateCertificate(bis), adm, newSignEntity) ) {
                        fileType="PEM";
                    }
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
    	synchronized(this) {
    	    if ( (this.signEntity != null) && (this.signEntity.size() > 0) && (this.servlet.mKeysValidTo > new Date().getTime()) ) {
    	        m_log.trace("<loadPrivateKeys: using cache");
    	        return;
    	    }
    	    // Update cache time
    	    // If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
    	    this.servlet.mKeysValidTo = this.servlet.m_valid_time>0 ? new Date().getTime()+this.servlet.m_valid_time : Long.MAX_VALUE;
    	}
        final HashMap<Integer, SigningEntity> newSignEntity = new HashMap<Integer, SigningEntity>();
        loadFromP11HSM(adm, newSignEntity);
        final File dir = this.mKeystoreDirectoryName!=null ? new File(this.mKeystoreDirectoryName) : null;
        if ( dir!=null && dir.isDirectory() ) {
            final File files[] = dir.listFiles();
            if ( files!=null && files.length>0 ) {
                for ( int i=0; i<files.length; i++ ) {
                    final String fileName = files[i].getCanonicalPath();
                    if ( !loadFromSWKeyStore(adm, fileName, newSignEntity) )
                        loadFromKeyCards(adm, fileName, newSignEntity);
                }
            } else {
            	m_log.debug("No files in directory: " + dir.getCanonicalPath());            	
                if ( newSignEntity.size()<1 ) {
                    throw new ServletException("No files in soft key directory: " + dir.getCanonicalPath());            	
                }
            }
        } else {
        	m_log.debug((dir != null ? dir.getCanonicalPath() : "null") + " is not a directory.");
            if ( newSignEntity.size()<1 ) {
                throw new ServletException((dir != null ? dir.getCanonicalPath() : "null") + " is not a directory.");
            }
        }
        // No P11 keys, there are files, but none are valid keys or certs for cards
        if ( newSignEntity.size()<1 ) {
        	String dirStr = (dir != null ? dir.getCanonicalPath() : "null");
            throw new ServletException("No valid keys in directory " + dirStr+", or in PKCS#11 keystore.");        	
        }
        this.signEntity = newSignEntity; // atomic change. after this new entity is used.
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
        void addKeyFactory(PrivateKeyContainer keyFactory);
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
        public void addKeyFactory(PrivateKeyContainer keyFactory) {
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
        public void addKeyFactory(PrivateKeyContainer keyFactory) {
            // do nothing
            
        }
    }
    private class P11ProviderHandler implements ProviderHandler {
        final private String name;
        private boolean isOK;
        final Set<PrivateKeyContainer> sKeyFacrory = new HashSet<PrivateKeyContainer>();
        P11ProviderHandler() throws Exception {
            this.name = OCSPServletStandAloneSession.this.slot.getProvider().getName();
            this.isOK = true;
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
                        final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyFacrory.iterator();
                        while ( i.hasNext() ) {
                            i.next().clear(); // clear all not useable old keys
                        }
                    }
                    OCSPServletStandAloneSession.this.slot.reset();
                    synchronized( this ) {
                        this.wait(10000); // wait 10 seconds to make system recover before trying again. all threads with ongoing operations has to stop
                    }
                    {
                        final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyFacrory.iterator();
                        while ( i.hasNext() ) {
                            PrivateKeyContainer pkf = i.next();
                            errorMessage = pkf.toString();
                            m_log.debug("Trying to reload: "+errorMessage);
                            pkf.set(P11ProviderHandler.this.getKeyStore(P11ProviderHandler.this.getPwd()));
                            m_log.info("Reloaded: "+errorMessage);
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
        public void addKeyFactory(PrivateKeyContainer keyFactory) {
            this.sKeyFacrory.add(keyFactory);
        }
    }
    private class SigningEntity {
        final private X509Certificate mChain[];
        final private PrivateKeyContainer mKeyFactory;
        final private ProviderHandler providerHandler;
        SigningEntity(X509Certificate c[], PrivateKeyContainer f, ProviderHandler ph) {
            this.mChain = c;
            this.mKeyFactory = f;
            this.providerHandler = ph;
        }
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
            final String hsmErrorString = "HSM not functional";
            final String providerName = this.providerHandler.getProviderName();
            final long HSM_DOWN_ANSWER_TIME = 15000; 
            if ( providerName==null ) {
                synchronized(this) {
                    try {
                        this.wait(HSM_DOWN_ANSWER_TIME); // Wait here to prevent the client repeat the request right away. Some CPU power might be needed to recover the HSM.
                    } catch (InterruptedException e) {
                        throw new Error(e); //should never ever happend. The main thread should never be interupted.
                    }
                }
                throw new ExtendedCAServiceRequestException(hsmErrorString+". Waited "+HSM_DOWN_ANSWER_TIME/1000+" seconds to throw the exception");
            }
            final PrivateKey privKey;
			try {
				privKey = this.mKeyFactory.getKey();
            } catch (ExtendedCAServiceRequestException e) {
                this.providerHandler.reload();
                throw e;
            } catch (Exception e) {
                this.providerHandler.reload();
                throw new ExtendedCAServiceRequestException(e);
            }
            if ( privKey==null ) {
                throw new ExtendedCAServiceRequestException(hsmErrorString);
            }
            try {
                return OCSPUtil.createOCSPCAServiceResponse(request, privKey, providerName, this.mChain);
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
    /**
     * Runnable that will do the response signing.
     * The signing is runned in a separate thread since it in rare occasion does not return.
     */
    private class SignerThread implements Runnable{
        final private SigningEntity se;
        final private OCSPCAServiceRequest request;
        private OCSPCAServiceResponse result = null;
        private ExtendedCAServiceRequestException extendedCAServiceRequestException = null;
        private IllegalExtendedCAServiceRequestException illegalExtendedCAServiceRequestException = null;
        SignerThread( SigningEntity _se, OCSPCAServiceRequest _request) {
            this.se = _se;
            this.request = _request;
        }
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        public void run() {
            OCSPCAServiceResponse _result = null;
            ExtendedCAServiceRequestException _extendedCAServiceRequestException = null;
            IllegalExtendedCAServiceRequestException _illegalExtendedCAServiceRequestException = null;
            try {
                _result = this.se.sign(this.request);
            } catch (ExtendedCAServiceRequestException e) {
                _extendedCAServiceRequestException = e;
            } catch (IllegalExtendedCAServiceRequestException e) {
                _illegalExtendedCAServiceRequestException = e;
            }
            synchronized(this) { // setting the results must be synchronized. The main thread may not access these attributes during this time.
                this.result = _result;
                this.extendedCAServiceRequestException = _extendedCAServiceRequestException;
                this.illegalExtendedCAServiceRequestException = _illegalExtendedCAServiceRequestException;
                this.notifyAll();
            }
        }
        /**
         * This method is called by the main thread to get the signing result. The method waits until the result is ready or until a timeout is reached.
         * @return the result
         * @throws ExtendedCAServiceRequestException
         * @throws IllegalExtendedCAServiceRequestException
         */
        synchronized OCSPCAServiceResponse getSignResult() throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
            final long HSM_TIMEOUT=30000; // in milliseconds
            if ( this.result==null && this.extendedCAServiceRequestException==null && this.illegalExtendedCAServiceRequestException==null ) {
                try {
                    this.wait(HSM_TIMEOUT);
                } catch (InterruptedException e) {
                    throw new Error(e);
                }
            }
            if ( this.illegalExtendedCAServiceRequestException!=null ) {
                throw this.illegalExtendedCAServiceRequestException;
            }
            if ( this.extendedCAServiceRequestException!=null ) {
                throw this.extendedCAServiceRequestException;
            }
            if ( this.result==null ) {
                throw new ExtendedCAServiceRequestException("HSM has not responded within time limit. The timeout is set to "+HSM_TIMEOUT/1000+" seconds.");
            }
            return this.result;
        }
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
            final SignerThread runnable = new SignerThread(se,request);
            final Thread thread = new Thread(runnable);
            thread.start();
            final OCSPCAServiceResponse result = runnable.getSignResult();
            thread.interrupt();
            return result;
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
        this.slot.removeProviderIfNoTokensActive();
        // should allways be active
        return true;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#isActive()
     */
    public boolean isActive() {
        return false; // it should allways be possible to clear the token
    }
}
