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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ocsp.OCSPUtil;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.P11Slot;
import org.ejbca.util.keystore.P11Slot.P11SlotUser;
import org.ejbca.util.provider.TLSProvider;
import org.ejbca.util.query.BasicMatch;

/** 
 * This instance is created when the OCSP Servlet session is initiated with {@link OCSPServletStandAlone#init()}. It will be only one instance of this class.
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class OCSPServletStandAloneSession implements P11SlotUser {

    /**
     * Log object.
     */
    static final private Logger m_log = Logger.getLogger(OCSPServletStandAloneSession.class);
    /**
     * Internal localization of logs and errors
     */
    private static final InternalResources intres = InternalResources.getInstance();
    /**
     * The directory containing all soft keys (p12s or jks) and all card certificates.
     */
    final private String mKeystoreDirectoryName = OcspConfiguration.getSoftKeyDirectoryName();
    /**
     * Password for all soft keys.
     */
    private String mKeyPassword = OcspConfiguration.getKeyPassword();
    /**
     * The password to all soft key stores.
     */
    private String mStorePassword = OcspConfiguration.getStorePassword();
	/**
	 * Reference to an object that holds all entities used for the OCSP signing.
	 */
	final private SigningEntityContainer signEntitycontainer;
    /**
     * Reference to the object that all information about the PKCS#11 slot.
     */
    final private P11Slot slot;
    /**
     * User password for the PKCS#11 slot. Used to logon to the slot.
     */
    private String mP11Password = OcspConfiguration.getP11Password();
    /**
     * The time before a OCSP signing certificate will expire that it should be removed.
     */
    final private int mRenewTimeBeforeCertExpiresInSeconds = OcspConfiguration.getRenewTimeBeforeCertExpiresInSeconds();
    /**
     * Reference to the servlet object.
     */
    final private OCSPServletStandAlone servlet;
    /**
     * The URL of the EJBCAWS used when "rekeying" is activated.
     */
    final private String webURL;
    /**
     * {@link #isNotReloadingP11Keys} tells if the servlet is ready to be used. It is false during the time when the HSM has failed until its keys is reloaded.
     */
    private boolean isNotReloadingP11Keys=true;
    /**
     * Password should not be stored in memory if this is true.
     */
    private final boolean doNotStorePasswordsInMemory = OcspConfiguration.getDoNotStorePasswordsInMemory();
    /**
     * Class name for "card" implementation.
     */
    private final String hardTokenClassName = OcspConfiguration.getHardTokenClassName();
    /**
     * Card password.
     */
    private String cardPassword = OcspConfiguration.getCardPassword();

    private final Set<String> keyAlias;
    /**
     * Called when a servlet is initialized. This should only occur once.
     * 
     * @param _servlet The servlet object.
     * @throws ServletException
     */
    OCSPServletStandAloneSession(OCSPServletStandAlone _servlet) throws ServletException {
        this.signEntitycontainer = new SigningEntityContainer();
        this.servlet = _servlet;
        try {
            if ( this.doNotStorePasswordsInMemory ) {
                final Set<String> sError = new HashSet<String>();
                if ( this.mStorePassword!=null ) {
                    sError.add(OcspConfiguration.STORE_PASSWORD);
                }
                if ( this.mP11Password!=null ) {
                    sError.add(OcspConfiguration.P11_PASSWORD);
                }
                if ( this.cardPassword!=null ) {
                    sError.add(OcspConfiguration.CARD_PASSWORD);
                }
                final StringWriter sw = new StringWriter();
                final PrintWriter pw = new PrintWriter(sw);
                if ( sError.size()>0 ) {
                    pw.print("When "+OcspConfiguration.DO_NOT_STORE_PASSWORDS_IN_MEMORY+" is configured you must remove these configurations: \"");
                    final Iterator<String> i = sError.iterator();
                    while( i.hasNext() ) {
                        pw.print(i.next());
                        if ( i.hasNext() )
                            pw.print("\" and \"");
                    }
                    pw.println("\".");
                }
                if ( OcspConfiguration.getSigningCertsValidTime()>0 ) {
                    pw.println("You must set "+OcspConfiguration.SIGNING_CERTD_VALID_TIME+" to 0 if "+OcspConfiguration.DO_NOT_STORE_PASSWORDS_IN_MEMORY+" is configured.");
                }
                pw.flush(); pw.close();
                final String error = sw.toString();
                if ( error!=null && error.length()>0 ) {
                    throw new ServletException(error);
                }
            }
            final boolean isIndex;
            final String sharedLibrary = OcspConfiguration.getSharedLibrary();
            final String configFile = OcspConfiguration.getSunP11ConfigurationFile();
            if ( sharedLibrary!=null && sharedLibrary.length()>0 ) {
                final String sSlot;
                final String sSlotRead = OcspConfiguration.getSlot();
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
                this.slot = P11Slot.getInstance(sSlot, sharedLibrary, isIndex, null, this, 0); // no CA, set id to 0 to indicate just one juser
    			m_log.debug("sharedLibrary is: "+sharedLibrary);
            } else if ( configFile!=null && configFile.length()>0 ) {
                this.slot = P11Slot.getInstance(configFile, this, 0); // no CA set caid to 0 to indicate only one user
                m_log.debug("Sun P11 configuration file is: "+configFile);
            } else {
            	this.slot = null;
            	m_log.debug("No shared P11 library.");
            }
            if ( this.mKeystoreDirectoryName==null || this.mKeystoreDirectoryName.length()<1 ) {
            	throw new ServletException(intres.getLocalizedMessage("ocsp.errornovalidkeys"));
            }
            m_log.debug("softKeyDirectoryName is: "+this.mKeystoreDirectoryName);
            this.webURL = OcspConfiguration.getEjbcawsracliUrl();
            if ( this.webURL!=null && this.webURL.length()>0 ){
                if ( this.mRenewTimeBeforeCertExpiresInSeconds<0 ) {
                    throw new ServletException(OcspConfiguration.RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS+" must be defined if "+OcspConfiguration.REKEYING_WSURL+" is defined.");
                }
                final String wsSwKeystorePath = OcspConfiguration.getWsSwKeystorePath();
                // Setting system properties to ssl resources to be used
                if ( wsSwKeystorePath!=null && wsSwKeystorePath.length()>0 ) {
                    final String password = OcspConfiguration.getWsSwKeystorePassword();
                    if ( password==null ) {
                        throw new ServletException(OcspConfiguration.WSSWKEYSTOREPASSWORD+" must be specified if "+OcspConfiguration.WSSWKEYSTOREPATH+" is specified.");
                    }
                    System.setProperty("javax.net.ssl.keyStore", wsSwKeystorePath);
                    System.setProperty("javax.net.ssl.keyStorePassword", password);
                } else if ( this.slot!=null ) {
                    System.setProperty("javax.net.ssl.keyStoreType", "pkcs11");
                    final String sslProviderName = this.slot.getProvider().getName();
                    if ( sslProviderName==null ) {
                        throw new ServletException("Problem with provider. No name.");
                    }
                    m_log.debug("P11 provider name for WS: "+sslProviderName);
                    System.setProperty("javax.net.ssl.keyStoreProvider", sslProviderName);
                    System.setProperty("javax.net.ssl.trustStore", "NONE");
                    System.setProperty("javax.net.ssl.keyStore", "NONE");
                } else {
                    throw new ServletException("If "+OcspConfiguration.REKEYING_WSURL+" is defined, either "+OcspConfiguration.WSSWKEYSTOREPATH+" or P11 must be defined.");
                }
                // setting ejbca trust provider that accept all server certs
                final Provider tlsProvider = new TLSProvider();
                Security.addProvider(tlsProvider);
                Security.setProperty("ssl.TrustManagerFactory.algorithm", "AcceptAll");
                Security.setProperty("ssl.KeyManagerFactory.algorithm", "NewSunX509");
            } else {
                if ( this.mRenewTimeBeforeCertExpiresInSeconds>=0 ) {
                    throw new ServletException(OcspConfiguration.RENEW_TIMR_BEFORE_CERT_EXPIRES_IN_SECONDS+" must not be defined if "+OcspConfiguration.REKEYING_WSURL+" is not defined.");
                }
                m_log.debug("Key renewal is not enabled.");
            }
            // Load OCSP responders private keys into cache in init to speed things up for the first request
            // signEntityMap is also set
            {
                final String aKeyAlias[] = OcspConfiguration.getKeyAlias();
                this.keyAlias = aKeyAlias!=null && aKeyAlias.length>0 ? new HashSet<String>(Arrays.asList(aKeyAlias)) : null;
            }
            loadPrivateKeys(this.servlet.m_adm, null);
        } catch( ServletException e ) {
            throw e;
        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
    /**
     * Tests a key.
     * @param privateKey The private part of the key.
     * @param publicKey The public part of the key.
     * @param alias The alias of the for the key. Just used for debug output.
     * @param providerName The provider name.
     * @return True if the key is OK.
     * @throws Exception
     */
    private boolean signTest(PrivateKey privateKey, PublicKey publicKey, String alias, String providerName) throws Exception {
        final String sigAlgName = "SHA1withRSA";
        final byte signInput[] = "Lillan gick on roaden ut.".getBytes();
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
            if (m_log.isDebugEnabled()) {
                m_log.debug("Signature test of key "+alias+
                        ": signature length " + signBA.length +
                        "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                        "; verifying " + result);            	
            }
        }
        return result;
    }
    /**
     * Fixes the answer for the call to {@link OCSPServletStandAlone#healthCheck()}
     * @return The answer to be returned by the health-check servlet.
     */
    String healthCheck() {
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        try {
            final Collection<SigningEntity> entityColleaction = this.signEntitycontainer!=null && this.signEntitycontainer.getSigningEntityMap()!=null ? this.signEntitycontainer.getSigningEntityMap().values() : null;
            if ( entityColleaction==null || entityColleaction.size()<1 ) {
                final String errMsg = intres.getLocalizedMessage("ocsp.errornosignkeys");
                pw.println();
                pw.print(errMsg);
                m_log.error(errMsg);
            } else {
                final Iterator<SigningEntity> i = entityColleaction.iterator();
                while ( i.hasNext() ) {
                    final SigningEntity signingEntity = i.next();
                    final String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", signingEntity.getCertificateChain()[1].getSubjectDN(), signingEntity.getCertificateChain()[0].getSerialNumber().toString(16));
                    if ( !signingEntity.isOK() ) {
                        pw.println();
                        pw.print(errMsg);
                        m_log.error("No key available. "+errMsg);
                        continue;
                    }
                    final X509Certificate entityCert = signingEntity.keyContainer.getCertificate();
                    final String providerName = signingEntity.providerHandler.getProviderName();
                    final PrivateKey privKey = signingEntity.keyContainer.getKey();
                    if ( privKey==null ) {
                        pw.println();
                        pw.print(errMsg);
                        m_log.error("No key available. "+errMsg);
                        continue;
                    }
                    try {
                        final boolean isOK = signTest(privKey, entityCert.getPublicKey(),
                                                      entityCert.getSubjectDN().toString(), providerName);
                        if ( !isOK ) {
                            pw.println();
                            pw.print(errMsg);
                            m_log.error("Key not working. "+errMsg);
                            continue;
                        }
                        if (m_log.isDebugEnabled()) {
                            m_log.debug("Test of \""+errMsg+"\" OK!");                        	
                        }
                    } finally {
                        signingEntity.keyContainer.releaseKey();
                    }
                }
            }
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            m_log.error(errMsg, e);
            pw.print(errMsg + ": "+e.getMessage());
        }
        pw.flush();
        return sw.toString();
    }
    /**
     * An object of this class is used to handle an OCSP signing key.
     */
    private interface PrivateKeyContainer {
        /**
         * Initiates the container. Start to wait to renew key.
         * @param chain the certificate chain for the key
         * @param caid the EJBCA id of the key.
         */
        void init(List<X509Certificate> chain, int caid);
        /**
         * Gets the OCSP signing key.
         * @return the key
         * @throws Exception
         */
        PrivateKey getKey() throws Exception;
        /**
         * Must allways be called after key has been used.
         */
        void releaseKey();
        /**
         * Sets the keystore to be used.
         * @param keyStore
         * @throws Exception
         */
        void set(KeyStore keyStore) throws Exception;
        /**
         * removes key
         */
        void clear();
        /**
         * Checks if key is OK to use
         * @return true if OK
         */
        boolean isOK();
        /**
         * Gets the cert
         * @return the certificate of the key
         */
        X509Certificate getCertificate();
        /**
         * Destroys the container. Waiting to renew keys stopped.
         */
        void destroy();
    }
    /**
     * Gets the P11 slot user password used to logon to a P11 session.
     * @param password Password to be used. Set to null if configured should be used
     * @return The password.
     */
    public PasswordProtection getP11Pwd(String password) {
        if ( password!=null ) {
            if ( this.mP11Password!=null ) {
                 m_log.error("Trying to activate even tought password has been configured.");
                 return null;
            }
            return new PasswordProtection(password.toCharArray());
        }
        if ( this.mP11Password!=null ) {
            return new PasswordProtection(this.mP11Password.toCharArray());
        }
        return null;
    }
    /**
     * Tells if we should renew a key before the certificate expires.
     * @return true if we should renew the key.
     */
    private boolean doKeyRenewal() {
        return this.webURL!=null && this.webURL.length()>0 && OCSPServletStandAloneSession.this.mRenewTimeBeforeCertExpiresInSeconds>=0;
    }
    /**
     * Implementation for java KeyStores. Could be SW or P11.
     *
     */
    private class PrivateKeyContainerKeyStore implements PrivateKeyContainer {
        /**
         * Alias of the in the {@link KeyStore} for this key.
         */
        final private String alias;
        /**
         * Certificate for this OCSP signing key.
         */
        private X509Certificate certificate;
        /**
         * The OCSP signing key.
         */
        private PrivateKey privateKey;
        /**
         * Object that runs a thread that is renewing a specified period before the certificate expires.
         */
        private KeyRenewer keyRenewer;
        /**
         * Key store holding this key.
         */
        private KeyStore keyStore;
        /**
         * True if the key is updating. {@link #getKey()} is halted when true.
         */
        private boolean isUpdatingKey;
        /**
         * Name of the provider to be used for signing.
         */
        final private String providerName;
        /**
         * Name of file where a newly generated key should be stored. Only used by SW keystores.
         */
        final private String fileName;
        /**
         * Nr of users using the key.
         */
        private int nrOfusers = 0;
        /**
         * Constructs the key reference.
         * @param a sets {@link #alias}
         * @param pw sets {@link #password}
         * @param _keyStore sets {@link #keyStore}
         * @param cert sets {@link #certificate}
         * @param _providerName sets {@link #providerName}
         * @param _fileName Only used SW keystores.
         * @throws Exception
         */
        PrivateKeyContainerKeyStore( String a, char pw[], KeyStore _keyStore, X509Certificate cert, String _providerName, String _fileName) throws Exception {
            this.alias = a;
            this.certificate = cert;
            this.keyStore = _keyStore;
            this.providerName = _providerName;
            this.fileName = _fileName;
            set(pw);
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#init(java.util.List, int)
         */
        public void init(List<X509Certificate> caChain, int caid) {
            destroy();
            if ( !doKeyRenewal() ) {
                return;
            }
            if ( this.fileName!=null && OCSPServletStandAloneSession.this.mStorePassword==null ) {
                m_log.error("Not possible to renew keys whith no stored keystore password for certificate with DN: "+caChain.get(0).getSubjectDN());
                return;
            }
            this.keyRenewer = new KeyRenewer(caChain, caid);
        }
        /**
         * Sets the private key.
         * @param pw The key password.
         * @throws Exception
         */
        private void set(char pw[]) throws Exception {
            this.privateKey = this.keyStore!=null ? (PrivateKey)this.keyStore.getKey(this.alias, pw) : null;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#set(java.security.KeyStore)
         */
        public void set(KeyStore _keyStore) throws Exception {
            this.keyStore = _keyStore;
            if ( this.fileName!=null && OCSPServletStandAloneSession.this.mKeyPassword==null ) {
                throw new Exception("Key password must be configured when reloading SW keystore.");
            }
            set(OCSPServletStandAloneSession.this.mKeyPassword.toCharArray());
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#clear()
         */
        public void clear() {
            this.privateKey = null;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getKey()
         */
        public PrivateKey getKey() throws Exception {
            synchronized(this) {
                while( this.isUpdatingKey ) {
                    this.wait();
                }
            }
            if ( this.privateKey==null ) {
                return null;
            }
            synchronized(this.privateKey) {
                this.nrOfusers++;
                return this.privateKey;
            }
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#releaseKey()
         */
        public void releaseKey() {
            if ( this.privateKey==null ) {
                m_log.warn("This should never ever happen. But if it does things may work afterwards anyway.");
                this.nrOfusers--;
                return;
            }
            synchronized(this.privateKey) {
                this.nrOfusers--;
                if ( this.nrOfusers<1 ) {
                    this.privateKey.notifyAll();
                }
            }
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#isOK()
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
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getCertificate()
         */
        public X509Certificate getCertificate() {
            return this.certificate;
        }
        /**
         * An object of this class is constructed when the key should be updated.
         */
        private class KeyRenewer {
            /**
             * Defines the thread that is doing the update.
             */
            final private Runner runner;
            /**
             * True as long as the object should renew the key when needed. Set to false when all signing entitys are reloaded.
             */
            private boolean doUpdateKey;
            /**
             * The CA chain. The CA signing the certificate for the new key is on top
             */
            final private List<X509Certificate> caChain;
            /**
             * EJBCA id for the CA that will sign the new key.
             */
            final private int caid;            
            /**
             * Class used for the thread doing the renewing.
             */
            private class Runner implements Runnable {
                /* (non-Javadoc)
                 * @see java.lang.Runnable#run()
                 */
                public synchronized void run() {
                    while( KeyRenewer.this.doUpdateKey ) {
                        if ( PrivateKeyContainerKeyStore.this.certificate==null ) {
                            return;
                        }
                        final long timeToRenew = PrivateKeyContainerKeyStore.this.certificate.getNotAfter().getTime()-new Date().getTime()-1000*(long)OCSPServletStandAloneSession.this.mRenewTimeBeforeCertExpiresInSeconds;
                        if (m_log.isDebugEnabled()) {
                            m_log.debug("time to renew signing key for CA \'"+PrivateKeyContainerKeyStore.this.certificate.getIssuerDN()+"\' : "+timeToRenew );
                        }
                        try {
                            wait(Math.max(timeToRenew, 15000)); // set to 15 seconds if long time to renew before expire 
                        } catch (InterruptedException e) {
                            throw new Error(e);
                        }
                        try {
                            updateKey();
                        } catch( Throwable t ) {
                            m_log.error("Unknown problem when rekeying. Trying again.", t);
                        }
                    }
                }
            }
            /**
             * Updating of the key.
             */
            private void updateKey() {
                if ( !this.doUpdateKey ) {
                    return;
                }
                setNextKeyUpdate(new Date().getTime()); //  since a key is now reloaded we should wait an whole interval for next key update
                m_log.debug("rekeying started for CA \'"+PrivateKeyContainerKeyStore.this.certificate.getIssuerDN()+"\'");
                // Check that we at least potentially have a RA key available for P11 sessions
                if ("pkcs11".equalsIgnoreCase(System.getProperty("javax.net.ssl.keyStoreType")) && OCSPServletStandAloneSession.this.mP11Password == null &&
                        !OCSPServletStandAloneSession.this.doNotStorePasswordsInMemory) {
                    m_log.info("PKCS#11 slot password is not yet available. Cannot access RA admin key until token is activated.");
                    return;
                }
                // TODO: If the password for the RA token was wrong, the SSL provider will crash and burn.. solve this.
                final EjbcaWS ejbcaWS = getEjbcaWS();
                if ( ejbcaWS==null ) {
                    return;
                }
                final String caName = getCAName(ejbcaWS);
                if ( caName==null ) {
                    m_log.debug("No CA for caid "+this.caid+" found.");
                    return;
                }
                final UserDataVOWS userData=getUserDataVOWS(ejbcaWS, caName);
                if ( userData==null ) {
                    return;
                }
                m_log.debug("user name found: "+ userData.getUsername());
                try {
                    waitUntilKeyIsNotUsed();
                    final KeyPair keyPair = generateKeyPair();
                    if ( keyPair==null ) {
                        return;
                    }
                    m_log.debug("public key: "+keyPair.getPublic() );
                    if ( !editUser(ejbcaWS, userData) ) {
                        return;
                    }
                    final X509Certificate certChain[] = storeKey(ejbcaWS, userData, keyPair);
                    if ( certChain==null ) {
                        return;
                    }
                    PrivateKeyContainerKeyStore.this.privateKey = keyPair.getPrivate();
                    PrivateKeyContainerKeyStore.this.certificate = certChain[0];
                } finally {
                    PrivateKeyContainerKeyStore.this.keyGenerationFinished();
                }
                m_log.info("New OCSP signing key generated for CA '"+ userData.getCaName()+"'. Username: '"+userData.getUsername()+"'. Subject DN: '"+userData.getSubjectDN()+"'.");
            }
            /**
             * Get WS object.
             * @return the EJBCA WS object.
             */
            private EjbcaWS getEjbcaWS() {
                final URL ws_url;
                try {
                    ws_url = new URL(OCSPServletStandAloneSession.this.webURL + "?wsdl");
                } catch (MalformedURLException e) {
                    m_log.error("Problem with URL: '"+OCSPServletStandAloneSession.this.webURL+"'", e);
                    return null;
                }
                final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
                m_log.debug("web service. URL: "+ws_url+" QName: "+qname);
                return new EjbcaWSService(ws_url, qname).getEjbcaWSPort();
            }
            /**
             * Get the CA name
             * @param ejbcaWS from {@link #getEjbcaWS()}
             * @return the name
             */
            private String getCAName(EjbcaWS ejbcaWS) {
                    final Map<Integer, String> mCA = new HashMap<Integer, String>();
                    final Iterator<NameAndId> i;
                    try {
                        i = ejbcaWS.getAvailableCAs().iterator();
                    } catch (Exception e) {
                        m_log.error("WS not working", e);
                        return null;
                    }
                    while( i.hasNext() ) {
                        final NameAndId nameAndId = i.next();
                        mCA.put(new Integer(nameAndId.getId()), nameAndId.getName());
                        m_log.debug("CA. id: "+nameAndId.getId()+" name: "+nameAndId.getName());
                    }
                    return mCA.get(new Integer(this.caid));
            }
            /**
             * Get user data for the EJBCA user that will be used when creating the cert for the new key.
             * @param ejbcaWS from {@link #getEjbcaWS()}
             * @param caName from {@link #getCAName(EjbcaWS)}
             * @return the data
             */
            private UserDataVOWS getUserDataVOWS(EjbcaWS ejbcaWS, String caName) {
                final UserMatch match = new org.ejbca.core.protocol.ws.client.gen.UserMatch();
                final String subjectDN = CertTools.getSubjectDN(PrivateKeyContainerKeyStore.this.certificate);
                match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
                match.setMatchvalue(subjectDN);
                match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
                final List<UserDataVOWS> result;
                try {
                    result = ejbcaWS.findUser(match);
                } catch (Exception e) {
                    m_log.error("WS not working", e);
                    return null;
                }
                if ( result==null || result.size()<1) {
                    m_log.info("no match for subject DN:"+subjectDN);
                    return null;
                }
                m_log.debug("at least one user found for cert with DN: "+subjectDN+" Trying to match it with CA name: "+caName);
                UserDataVOWS userData = null;
                final Iterator<UserDataVOWS> i = result.iterator();
                while ( i.hasNext() ) {
                    final UserDataVOWS tmpUserData = i.next();
                    if ( caName.equals(tmpUserData.getCaName()) ) {
                        userData = tmpUserData;
                        break;
                    }
                }
                if ( userData==null ) {
                    m_log.error("No user found for certificate '"+subjectDN+"' on CA '"+caName+"'.");
                    return null;
                }
                return userData;
            }
            /**
             * Generate the key.
             * @return the key
             */
            private KeyPair generateKeyPair() {

                final RSAPublicKey oldPublicKey; {
                    final PublicKey tmpPublicKey = PrivateKeyContainerKeyStore.this.certificate.getPublicKey();
                    if ( !(tmpPublicKey instanceof RSAPublicKey) ) {
                        m_log.error("Only RSA keys could be renewed.");
                        return null;
                    }
                    oldPublicKey = (RSAPublicKey)tmpPublicKey;
                }
                final KeyPairGenerator kpg;
                try {
                    kpg = KeyPairGenerator.getInstance("RSA", PrivateKeyContainerKeyStore.this.providerName);
                    kpg.initialize(oldPublicKey.getModulus().bitLength());
                    return kpg.generateKeyPair();
                } catch (Throwable e) {
                    m_log.error("Key generation problem.", e);
                    return null;
                }
            }
            /**
             * setting status of EJBCA user to new and setting password of user.
             * @param ejbcaWS from {@link #getEjbcaWS()}
             * @param userData from {@link #getUserDataVOWS(EjbcaWS, String)}
             * @return true if success
             */
            private boolean editUser(EjbcaWS ejbcaWS, UserDataVOWS userData) {
                userData.setStatus(UserDataConstants.STATUS_NEW);
                userData.setPassword("foo123");
                userData.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
                try {
                    ejbcaWS.editUser(userData);
                } catch (Exception e) {
                    m_log.error("Problem to edit user.", e);
                    return false;
                }
                return true;
            }
            /**
             * Fetch a new certificate from EJBCA and stores the key with the certificate chain.
             * @param ejbcaWS from {@link #getEjbcaWS()}
             * @param userData from {@link #getUserDataVOWS(EjbcaWS, String)}
             * @param keyPair from {@link #generateKeyPair()}
             * @return the certificate chain of the stored key
             */
            private X509Certificate[] storeKey(EjbcaWS ejbcaWS, UserDataVOWS userData, KeyPair keyPair) {
                X509Certificate tmpCert = null;
                final Iterator<X509Certificate> i;
                try {
                    final PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", CertTools.stringToBcX509Name("CN=NOUSED"), keyPair.getPublic(), new DERSet(),
                                                                                             keyPair.getPrivate(), PrivateKeyContainerKeyStore.this.providerName );
                    final CertificateResponse certificateResponse = ejbcaWS.pkcs10Request(userData.getUsername(), userData.getPassword(),
                                                                                          new String(Base64.encode(pkcs10.getEncoded())),null,CertificateHelper.RESPONSETYPE_CERTIFICATE);
                    i = (Iterator<X509Certificate>)CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(Base64.decode(certificateResponse.getData()))).iterator();
                } catch (Exception e) {
                    m_log.error("Certificate generation problem.", e);
                    return null;
                }
                while ( i.hasNext() ) {
                    tmpCert = i.next();
                    try {
                        tmpCert.verify(this.caChain.get(0).getPublicKey());
                    } catch (Exception e) {
                        tmpCert = null;
                        continue;
                    }
                    if ( keyPair.getPublic().equals(tmpCert.getPublicKey()) )
                        break;
                    tmpCert = null;
                }
                if ( tmpCert==null ) {
                    m_log.error("No certificate signed by correct CA generated.");
                    return null;
                }
                final List<X509Certificate> lCertChain = new ArrayList<X509Certificate>(this.caChain);
                lCertChain.add(0, tmpCert);
                final X509Certificate certChain[] = lCertChain.toArray(new X509Certificate[0]);
                if ( PrivateKeyContainerKeyStore.this.fileName!=null && OCSPServletStandAloneSession.this.mKeyPassword==null ) {
                    m_log.error("Key password must be configured when updating SW keystore.");
                    return null;
                }
                try {
                    PrivateKeyContainerKeyStore.this.keyStore.setKeyEntry(PrivateKeyContainerKeyStore.this.alias, keyPair.getPrivate(),
                                                                          OCSPServletStandAloneSession.this.mKeyPassword!=null ? OCSPServletStandAloneSession.this.mKeyPassword.toCharArray() : null,
                                                                          certChain);
                } catch (Throwable e) {
                    m_log.error("Problem to store new key in HSM.", e);
                    return null;
                }
                if ( PrivateKeyContainerKeyStore.this.fileName!=null ) {
                    try {
                        PrivateKeyContainerKeyStore.this.keyStore.store(new FileOutputStream(PrivateKeyContainerKeyStore.this.fileName),
                                                                        OCSPServletStandAloneSession.this.mStorePassword.toCharArray());
                    } catch (Throwable e) {
                        m_log.error("Not possible to store keystore on file.",e);
                    }
                }
                return certChain;
            }
            /**
             * Initialize renewing of keys.
             * @param _caChain sets {@link #caChain}
             * @param _caid sets {@link #caid}
             */
            KeyRenewer(List<X509Certificate> _caChain, int _caid) {
                this.caid = _caid;
                this.caChain = _caChain;
                this.doUpdateKey = false;
                if ( doKeyRenewal() ) {
                    this.runner = new Runner();
                    this.doUpdateKey = true;
                    new Thread(this.runner).start();
                } else {
                    this.runner = null;
                }
            }
            /**
             * Shuts down the rekeying thread. Done when reloading OCSP signing keys.
             */
            void shutdown() {
                this.doUpdateKey = false;
                if ( this.runner!=null ) {
                    synchronized( this.runner ) {
                        this.runner.notifyAll();
                    }
                }
            }
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#destroy()
         */
        public void destroy() {
            if ( this.keyRenewer!=null ) {
                this.keyRenewer.shutdown();
            }
        }
        /**
         * Notify that key-generation has ended.
         */
        private synchronized void keyGenerationFinished() {
            this.isUpdatingKey = false;
            this.notifyAll();
        }
        /**
         * Wait until key is not used. Used before key generation is started.
         */
        private void waitUntilKeyIsNotUsed() {
            synchronized(this) {
                this.isUpdatingKey = true;
            }
            if ( this.privateKey==null ) {
                m_log.warn("This should never ever happen. But if it does things may work afterwards anyway.");
                if ( this.nrOfusers>0 ) {
                    throw new Error("No private key in '"+this.toString()+"'. Still used by "+this.nrOfusers+" users.");
                }
                return;
            }
            synchronized(this.privateKey) {
                while( this.nrOfusers>0 ) {
                    try {
                        this.privateKey.wait();
                    } catch (InterruptedException e) {
                        new Error(e); // should never happen.
                    }
                }
            }
        }
    }
    /**
     * Card implementation.
     */
    private class PrivateKeyContainerCard implements PrivateKeyContainer {
        /**
         * The signing certificate.
         */
        final private X509Certificate certificate;
        /**
         * The keys on the card.
         */
        final private CardKeys cardKeys;
        /**
         * Initiates the object.
         * @param cert the signing certificate
         * @param keys The keys on the card.
         */
        PrivateKeyContainerCard( X509Certificate cert, CardKeys keys) {
            this.certificate = cert;
            this.cardKeys = keys;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getKey()
         */
        public PrivateKey getKey() throws Exception {
            return this.cardKeys.getPrivateKey((RSAPublicKey)this.certificate.getPublicKey());
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#releaseKey()
         */
        public void releaseKey() {
            // not used by cards since no rekeying
        }
		/* (non-Javadoc)
		 * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#isOK()
		 */
		public boolean isOK() {
			return this.cardKeys.isOK((RSAPublicKey)this.certificate.getPublicKey());
		}
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#clear()
         */
        public void clear() {
            // not used by cards.
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#set(java.security.KeyStore)
         */
        public void set(KeyStore keyStore) throws Exception {
            // not used by cards.
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#getCertificate()
         */
        public X509Certificate getCertificate() {
            return this.certificate;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#init(java.util.List, int)
         */
        public void init(List<X509Certificate> name, int caid) {
            // do nothing
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer#destroy()
         */
        public void destroy() {
            // do nothing
        }
    }
    /**
     * Holds a {@link SigningEntity} for each CA that the responder is capable of signing a response for.
     */
    private class  SigningEntityContainer {
        /**
         * Mapping of {@link SigningEntity} to EJBCA CA ID.
         */
        private Map<Integer, SigningEntity> signEntityMap;
        /**
         * Mutex used to assure that only one thread is executing a part of the code at a time.
         */
        private Mutex mutex = new Mutex();
        /**
         * Flag telling if the {@link #signEntityMap} is beeing updated.
         */
        private boolean updating = false;
        /**
         * Refernece of the object that handles all card OCSP signing keys.
         */
        private CardKeys cardKeys;
        /**
         * Last try of key reload.
         */
        private long lastTryOfKeyReload;
        /**
         * The implementation of the mutex.
         */
        private class Mutex {
            /**
             * This flag is true when this mutex is owned by a thread
             */
            private boolean locked;
            /**
             * Construct a mutex initially not owned by any thread,
             */
            Mutex() {
                super();
                this.locked = false;
                m_log.debug("mutex created.");
            }
            /**
             * Get ownership of the mutex.
             */
            synchronized void getMutex() {
                while( this.locked ) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        throw new Error(e);
                    }
                }
                this.locked = true;
            }
            /**
             * Give away the mutex.
             */
            synchronized void releaseMutex() {
                this.locked = false;
                this.notify();
            }
        }
        /**
         * Test if all criterias for key loading is fulfilled.
         * If it is {@link #loadPrivateKeys2(Admin, String)} is called after calculating time fot new update.
         * @param adm Administrator to be used when getting the certificate chain from the DB.
         * @param password This password is only set if passwords should not be stored in memory.
         * @throws Exception
         */
        void loadPrivateKeys(final Admin adm, final String password ) throws Exception {
            try {
                this.mutex.getMutex();
                final long currentTime = new Date().getTime();
                // We will only load private keys if the cache time has run out
                if ( password==null && (
                        this.updating || this.lastTryOfKeyReload+10000>currentTime || !OCSPServletStandAloneSession.this.isNotReloadingP11Keys ||
                        (this.signEntityMap!=null && this.signEntityMap.size()>0 && OCSPServletStandAloneSession.this.servlet.mKeysValidTo>currentTime)
                ) ) {
                    return;
                }
                setNextKeyUpdate(currentTime);// set next time for key loading
            } finally {
                this.mutex.releaseMutex();
            }
            try {
            	if (m_log.isTraceEnabled()) {
                    m_log.trace(">loadPrivateKeys2");
            	}
                this.updating  = true; // stops new action on token
                loadPrivateKeys2(adm, password);
            } finally {
                this.lastTryOfKeyReload = new Date().getTime();
                synchronized(this) {
                    this.updating = false;
                    this.notifyAll();
                }
            	if (m_log.isTraceEnabled()) {
                    m_log.trace("<loadPrivateKeys2");
            	}
            }
        }
        /**
         * Create a {@link SigningEntity} for all OCSP signing keys that could be found.
         * @param adm Administrator to be used when getting the certificate chain from the DB.
         * @param password This password is only set if passwords should not be stored in memory.
         * @throws Exception
         */
        private void loadPrivateKeys2(Admin adm, String password ) throws Exception {
            if ( this.signEntityMap!=null ){
                Collection<SigningEntity> values=this.signEntityMap.values();
                if ( values!=null ) {
                    final Iterator<SigningEntity> i = values.iterator();
                    while( i.hasNext() ) {
                        i.next().shutDown();
                    }
                }
            }
            if ( this.cardKeys==null && OCSPServletStandAloneSession.this.hardTokenClassName!=null && OCSPServletStandAloneSession.this.hardTokenClassName.length()>0 ) {
                final String tmpPassword = password!=null ? password : OCSPServletStandAloneSession.this.cardPassword;
                if ( tmpPassword!=null  ) {
                    try {
                        this.cardKeys = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(OCSPServletStandAloneSession.this.hardTokenClassName).newInstance();
                        this.cardKeys.autenticate(tmpPassword);
                    } catch( ClassNotFoundException e) {
                        m_log.info(intres.getLocalizedMessage("ocsp.classnotfound", OCSPServletStandAloneSession.this.hardTokenClassName));
                    }
                } else {
                    m_log.info(intres.getLocalizedMessage("ocsp.nocardpwd"));
                }
            } else {
                m_log.info( intres.getLocalizedMessage("ocsp.nohwsigningclass") );
            }
            final HashMap<Integer, SigningEntity> newSignEntity = new HashMap<Integer, SigningEntity>();
            synchronized(this) {
                this.wait(500); // wait for actions on token to get ready
            }
            loadFromP11HSM(adm, newSignEntity, password);
            final File dir = OCSPServletStandAloneSession.this.mKeystoreDirectoryName!=null ? new File(OCSPServletStandAloneSession.this.mKeystoreDirectoryName) : null;
            if ( dir!=null && dir.isDirectory() ) {
                final File files[] = dir.listFiles();
                if ( files!=null && files.length>0 ) {
                    for ( int i=0; i<files.length; i++ ) {
                        final String fileName = files[i].getCanonicalPath();
                        if ( !loadFromSWKeyStore(adm, fileName, newSignEntity, password) ) {
                            loadFromKeyCards(adm, fileName, newSignEntity);
                        }
                    }
                } else {
                    m_log.debug("No files in soft key directory: " + dir.getCanonicalPath());
                }
            } else {
                m_log.debug((dir != null ? dir.getCanonicalPath() : "null") + " is not a directory.");
            }
            if ( newSignEntity.size()<1 ) {
                String sError = "No valid keys.";
                {
                    final String dirStr = dir!=null ? dir.getCanonicalPath() : null;
                    if ( dirStr!=null ) {
                        sError += " Key directory "+dirStr+".";
                    } else {
                        sError += " No key directory.";
                    }
                }{
                    final String p11name = OCSPServletStandAloneSession.this.slot!=null && OCSPServletStandAloneSession.this.slot.getProvider()!=null ? OCSPServletStandAloneSession.this.slot.getProvider().getName() : null;
                    if ( p11name!=null ) {
                        sError += " P11 provider "+p11name+".";
                    } else {
                        sError += " No P11 defined.";
                    }
                }
                m_log.error(sError);
            }
            {
                final Iterator<Entry<Integer, SigningEntity>> i=newSignEntity.entrySet().iterator();
                while( i.hasNext() ) {
                    Entry<Integer, SigningEntity> entry = i.next();
                    entry.getValue().init(entry.getKey().intValue());
                }
            }
            this.signEntityMap = newSignEntity; // atomic change. after this new entity is used.
        }
        /**
         * Gets all {@link SigningEntity}s mapped to EJBCA CA IDs.
         * @return The map.
         */
        synchronized Map<Integer, SigningEntity> getSigningEntityMap() {
            while ( this.updating ) {
                try {
                    this.wait();
                } catch (InterruptedException e) {
                    throw new Error(e);
                }
            }
            return this.signEntityMap;
        }
        /**
         * Adds OCSP signing keys from the HSM to the newSignEntity (parameter).
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param newSignEntity The map where the signing entity should be stored for all keys found where the certificate is a valid OCSP certificate.
         * @param password Used for activation.
         * @return true if keys where found on the HSM
         * @throws Exception
         */
        private boolean loadFromP11HSM(Admin adm, Map<Integer, SigningEntity> newSignEntity,
                                       String password) {
            final PasswordProtection pwp = getP11Pwd(password);
            if ( !checkPassword( pwp, OcspConfiguration.P11_PASSWORD) ) {
                return false;
            }
            if ( OCSPServletStandAloneSession.this.slot==null ) {
                m_log.debug("no shared library");
                return false;           
            }
            OCSPServletStandAloneSession.this.slot.reset();
            try {
                final P11ProviderHandler providerHandler = new P11ProviderHandler();
                loadFromKeyStore(adm, providerHandler.getKeyStore(pwp), null,
                                 OCSPServletStandAloneSession.this.slot.toString(),
                                 providerHandler, newSignEntity, null);
                pwp.destroy();
            } catch( Exception e) {
                m_log.error("load from P11 problem", e);
                return false;
            }
            return true;
        }
        /**
         * Waits 10 if no password object.
         * @param passObject The password object.
         * @param passPropertyKey Property key to define 
         * @return Is password not null.
         */
        private boolean checkPassword( Object passObject, String passPropertyKey ) {
            if ( passObject!=null )  {
                return true;
            }
            m_log.warn("You have not specified "+passPropertyKey+" at build time. So you need to do a manual activation.");
            return false;
        }
        /**
         * Adds the OCSP signing key from the java SW keystore to the newSignEntity (parameter).
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param fileName The name of a file with a SW java keystore.
         * @param newSignEntity The map where the signing entity should be stored for the key if the certificate is a valid OCSP certificate.
         * @return true if the key in the SW java keystore was valid.
         */
        private boolean loadFromSWKeyStore(Admin adm, String fileName, HashMap<Integer, SigningEntity> newSignEntity,
                                           String password) {
            try {
                final String storePassword = OCSPServletStandAloneSession.this.mStorePassword!=null ? OCSPServletStandAloneSession.this.mStorePassword : password;
                if ( !checkPassword( storePassword, OcspConfiguration.STORE_PASSWORD) ) {
                    return false;
                }
                m_log.trace(">loadFromSWKeyStore");
                KeyStore keyStore;
                try {
                    keyStore = KeyStore.getInstance("JKS");
                    keyStore.load(new FileInputStream(fileName), storePassword.toCharArray());
                } catch( IOException e ) {
                    keyStore = KeyStore.getInstance("PKCS12", "BC");
                    keyStore.load(new FileInputStream(fileName), storePassword.toCharArray());
                }
                final String keyPassword = OCSPServletStandAloneSession.this.mKeyPassword!=null ? OCSPServletStandAloneSession.this.mKeyPassword : password;
                loadFromKeyStore(adm, keyStore, keyPassword, fileName, new SWProviderHandler(), newSignEntity, fileName);
                m_log.trace("<loadFromSWKeyStore OK");
                return true;
            } catch( Exception e ) {
                m_log.debug("Unable to load key file "+fileName+". Exception: "+e.getMessage());
            }
            m_log.trace("<loadFromSWKeyStore failed");
            return false;
        }
        /**
         * Is OCSP extended key usage set for a certificate?
         * @param cert to check.
         * @return true if the extended key usage for OCSP is check
         */
        private boolean isOCSPCert(X509Certificate cert) {
            final String ocspKeyUsage = "1.3.6.1.5.5.7.3.9";
            final List<String> keyUsages;
            try {
                keyUsages = cert.getExtendedKeyUsage();
            } catch (CertificateParsingException e) {
                return false;
            }
            return keyUsages!=null && keyUsages.contains(ocspKeyUsage);
        }
        /**
         * Adds OCSP signing keys from a java keystore to the newSignEntity (parameter).
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param keyStore The keystore.
         * @param keyPassword Password for the key. Set to null if not protected.
         * @param errorComment Comment to be used in possible error message.
         * @param providerHandler The provider to be used.
         * @param newSignEntity The map where the signing entity should be stored for all keys found where the certificate is a valid OCSP certificate.
         * @param fileName Name of the keystore file. Use null for P11
         * @throws KeyStoreException
         */
        private void loadFromKeyStore(Admin adm, KeyStore keyStore, String keyPassword,
                                      String errorComment, ProviderHandler providerHandler,
                                      Map<Integer, SigningEntity> newSignEntity, String fileName) throws KeyStoreException {
            final Enumeration<String> eAlias = keyStore.aliases();
            while( eAlias.hasMoreElements() ) {
                final String alias = eAlias.nextElement();
                if ( OCSPServletStandAloneSession.this.keyAlias!=null && !OCSPServletStandAloneSession.this.keyAlias.contains(alias) ) {
                    m_log.debug("Alias '"+alias+"' not in alias list. The key with this alias will not be used.");
                    continue;
                }
                try {
                    final X509Certificate cert = (X509Certificate)keyStore.getCertificate(alias);
                    if ( cert==null ) {
                        m_log.debug("No certificate found for keystore alias '"+alias+"'");
                        continue;
                    }
                    if ( !isOCSPCert(cert) ) {
                        m_log.debug("Certificate "+cert.getSubjectDN()+" has not ocsp signing as extended key usage"+"', keystore alias '"+alias+"'");
                        continue;
                    }
                    final PrivateKeyContainer pkf = new PrivateKeyContainerKeyStore( alias, keyPassword!=null ? keyPassword.toCharArray() : null,
                                                                                     keyStore, cert, providerHandler.getProviderName(), fileName );
                    final PrivateKey key = pkf.getKey();
                    if ( key==null ) {
                        m_log.debug("Key not available. Not adding signer entity for: "+cert.getSubjectDN()+"', keystore alias '"+alias+"'");
                        continue;
                    }
                    try {
                        if ( !signTest(key, cert.getPublicKey(), errorComment, providerHandler.getProviderName()) ) {
                            m_log.debug("Key not working. Not adding signer entity for: "+cert.getSubjectDN()+"', keystore alias '"+alias+"'");
                            continue;
                        }
                        m_log.debug("Adding sign entity for '"+cert.getSubjectDN()+"', keystore alias '"+alias+"'");
                        putSignEntity(pkf, cert, adm, providerHandler, newSignEntity);
                    } finally {
                        pkf.releaseKey();
                    }
                } catch (Exception e) {
                    String errMsg = intres.getLocalizedMessage("ocsp.errorgetalias", alias, errorComment);
                    m_log.error(errMsg, e);
                }
            }
        }
        /**
         * Gets the chain for a certificate. The certificate must be valid and in the DB.
         * @param cert The certificate that should be first in the chain.
         * @param adm  Administrator performing the operation. 
         * @return The chain of the certificate. Null if the certificate is not valid.
         */
        private List<X509Certificate> getCertificateChain(X509Certificate cert, Admin adm) {
            String issuerDN = CertTools.getIssuerDN(cert);
            final CertificateStatus status = OCSPServletStandAloneSession.this.servlet.getStatus(issuerDN, CertTools.getSerialNumber(cert));
            if ( status.equals(CertificateStatus.NOT_AVAILABLE) ) {
                m_log.warn(intres.getLocalizedMessage("ocsp.signcertnotindb", CertTools.getSerialNumberAsString(cert), issuerDN));
                return null;
            }
            if ( status.equals(CertificateStatus.REVOKED) ) {
                m_log.warn(intres.getLocalizedMessage("ocsp.signcertrevoked", CertTools.getSerialNumberAsString(cert), issuerDN));
                return null;
            }
            final List<X509Certificate> list = new ArrayList<X509Certificate>();
            X509Certificate current = cert;
            while( true ) {
                if ( CertTools.isSelfSigned(current) ) {
                    return list;
                }
                // Is there a CA certificate?
                final X509Certificate target = OCSPServletStandAloneSession.this.servlet.m_caCertCache.findLatestBySubjectDN(CertTools.getIssuerDN(current));
                if (target != null) {
                    current = target;
                    list.add(current);
                } else {
                    break;              
                }
            }
            m_log.warn(intres.getLocalizedMessage("ocsp.signcerthasnochain", CertTools.getSerialNumberAsString(cert), issuerDN));
            return null;
        }
        /**
         * Constructs a new {@link SigningEntity} and puts it in the map 'newSignEntitys'.
         * If 'newSignEntitys' allready contains a certificate for the same CA which is newer than 'cert' the one in the map is kept (nothing is done).
         * @param keyContainer The key.
         * @param cert The certificate of the key
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param providerHandler The provider.
         * @param newSignEntitys The map where the signing entity should be stored for all keys found where the certificate is a valid OCSP certificate.
         * @return true if the key and certificate are valid for OCSP signing for one of the EJBCA CAs.
         */
        private boolean putSignEntity( PrivateKeyContainer keyContainer, X509Certificate cert, Admin adm, ProviderHandler providerHandler,
                                       final Map<Integer, SigningEntity> newSignEntitys) {
            if ( keyContainer==null || cert==null ) {
                return false;
            }
            final List<X509Certificate> chain = getCertificateChain(cert, adm);
            if ( chain==null || chain.size()<1 ) {
                return false;
            }
            final Integer caid = new Integer(OCSPServletStandAloneSession.this.servlet.getCaid(chain.get(0)));
            {
                final SigningEntity entityForSameCA = newSignEntitys.get(caid);
                final X509Certificate otherChainForSameCA[] = entityForSameCA!=null ? entityForSameCA.getCertificateChain() : null;
                if ( otherChainForSameCA!=null && otherChainForSameCA[0].getNotBefore().after(cert.getNotBefore())) {
                    m_log.debug("CA with ID "+caid+" has duplicated keys. Certificate for older key that is not used has serial number: "+cert.getSerialNumber().toString(0x10));
                    return true; // the entity already in the map is newer.
                }
            }
            newSignEntitys.put( caid, new SigningEntity(chain, keyContainer, providerHandler) );
            m_log.debug("CA with ID "+caid+" now has a OCSP signing key. Certificate with serial number: "+cert.getSerialNumber().toString(0x10));
            return true;
        }
        /**
         * Constructs a new {@link SigningEntity} and puts it in the map 'newSignEntitys'.
         * If 'newSignEntitys' allready contains a certificate for the same CA which is newer than 'cert' the one in the map is kept (nothing is done).
         * @param cert The certificate of the key
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param newSignEntity The map where the signing entity should be stored for all keys found where the certificate is a valid OCSP certificate.
         * @return true if the key and certificate are valid for OCSP signing for one of the EJBCA CAs.
         */
        private boolean putSignEntityCard( Certificate cert, Admin adm,
                                           Map<Integer, SigningEntity> newSignEntity) {
            if ( cert!=null &&  cert instanceof X509Certificate) {
                final X509Certificate x509cert = (X509Certificate)cert;
                final PrivateKeyContainer keyContainer = new PrivateKeyContainerCard(x509cert, this.cardKeys);
                return putSignEntity( keyContainer, x509cert, adm, new CardProviderHandler(), newSignEntity );
            }
            return false;
        }
        /**
         * Adds OCSP signing keys from the card to the newSignEntity (parameter).
         * @param adm Adminstrator to be used when getting the certificate chain from the DB.
         * @param fileName The name of the file where the certificates are stored.
         * @param newSignEntity The map where the signing entity should be stored for all keys found where the certificate is a valid OCSP certificate.
         */
        private void loadFromKeyCards(Admin adm, String fileName, Map<Integer, SigningEntity> newSignEntity) {
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
    }
    /**
     * Adds {@link SigningEntity} to the {@link SigningEntityContainer} object for all OCSP signing keys that could be found.
     * @param adm Adminstrator to be used when getting the certificate chain from the DB.
     * @param password Password for activation. If null then ust key loading.
     * @throws Exception
     */
    void loadPrivateKeys(Admin adm, String password) throws Exception {
        if ( this.doNotStorePasswordsInMemory ) {
            if ( password==null ) {
                return; // can not load without password.
            }
            this.signEntitycontainer.loadPrivateKeys(adm, password);
            return;
        }
        if ( password==null ) {
            this.signEntitycontainer.loadPrivateKeys(adm, null);
            return;
        }
        if ( this.mKeyPassword==null ) {
            this.mKeyPassword=password;
        }
        if ( this.mStorePassword==null ) {
            this.mStorePassword=password;
        }
        if ( this.mP11Password==null ) {
            this.mP11Password=password;
        }
        if ( this.cardPassword==null ) {
            this.cardPassword = password;
        }
        this.signEntitycontainer.loadPrivateKeys(adm, null);
    }
    /**
     * Set time for next key update.
     * @param currentTime the time from which the to measure next update.
     */
    private void setNextKeyUpdate(final long currentTime) {
        // Update cache time
        // If getSigningCertsValidTime() == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
        OCSPServletStandAloneSession.this.servlet.mKeysValidTo = OcspConfiguration.getSigningCertsValidTime()>0 ? currentTime+OcspConfiguration.getSigningCertsValidTime() : Long.MAX_VALUE;
        m_log.debug("time: "+currentTime+" next update: "+OCSPServletStandAloneSession.this.servlet.mKeysValidTo);
    }
    /**
     * Holds information about a provider.
     * Used to be able to reload a provider when a HSM has stoped working.
     * For other sub classes but {@link P11ProviderHandler} nothing is done at reload when {@link #reload()} is called.
     */
    private interface ProviderHandler {
        /**
         * Gets the name of the provider.
         * @return the name. null if the provider is not working (reloading).
         */
        String getProviderName();
        /**
         * Must be called for all {@link PrivateKeyContainer} objects using this object.
         * @param keyContainer {@link PrivateKeyContainer} to be updated at reload
         */
        void addKeyContainer(PrivateKeyContainer keyContainer);
        /**
         * Start a threads that tries to reload the provider until it is done or does nothing if reloading does't help.
         */
        void reload();
    }
    /**
     * Card implementation. No reload needed.
     */
    private class CardProviderHandler implements ProviderHandler {
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#getProviderName()
         */
        public String getProviderName() {
            return "PrimeKey";
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#reload()
         */
        public void reload() {
            // not needed to reload.
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#addKeyContainer(org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer)
         */
        public void addKeyContainer(PrivateKeyContainer keyContainer) {
            // do nothing
        }
    }
    /**
     * SW implementation. No reload needed.
     */
    private class SWProviderHandler implements ProviderHandler {
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#getProviderName()
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
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#addKeyContainer(org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer)
         */
        public void addKeyContainer(PrivateKeyContainer keyContainer) {
            // do nothing
        }
    }
    /**
     * P11 implementation. Reload the provider when {@link #reload()} is called.
     */
    private class P11ProviderHandler implements ProviderHandler {
        /**
         * Provider name.
         */
        final private String name;
        /**
         * Set of all {@link PrivateKeyContainer} using this provider.
         */
        final Set<PrivateKeyContainer> sKeyContainer = new HashSet<PrivateKeyContainer>();
        /**
         * Creation of the provider.
         * @throws Exception
         */
        P11ProviderHandler() throws Exception {
            this.name = OCSPServletStandAloneSession.this.slot.getProvider().getName();
        }
        /**
         * Get the keystore for the slot.
         * @param pwp the password for the slot
         * @return the keystore for the provider
         * @throws Exception
         */
        public KeyStore getKeyStore(PasswordProtection pwp) throws Exception {
            final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                                                                          OCSPServletStandAloneSession.this.slot.getProvider(),
                                                                          pwp);
            final KeyStore keyStore = builder.getKeyStore();
            m_log.debug("Loading key from slot '"+OCSPServletStandAloneSession.this.slot+"' using pin.");
            keyStore.load(null, null);
            return keyStore;
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#getProviderName()
         */
        public String getProviderName() {
            return OCSPServletStandAloneSession.this.isNotReloadingP11Keys ? this.name : null;
        }
        /**
         * An object of this class reloads the provider in a separate thread.
         */
        private class Reloader implements Runnable {
            /* (non-Javadoc)
             * @see java.lang.Runnable#run()
             */
            public void run() {
                String errorMessage ="";
                while ( true ) try {
                    errorMessage = "";
                    {
                        final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyContainer.iterator();
                        while ( i.hasNext() ) {
                            i.next().clear(); // clear all not useable old keys
                        }
                    }
                    OCSPServletStandAloneSession.this.slot.reset();
                    synchronized( this ) {
                        this.wait(10000); // wait 10 seconds to make system recover before trying again. all threads with ongoing operations has to stop
                    }
                    {
                        final Iterator<PrivateKeyContainer> i = P11ProviderHandler.this.sKeyContainer.iterator();
                        while ( i.hasNext() ) {
                            PrivateKeyContainer pkf = i.next();
                            errorMessage = pkf.toString();
                            m_log.debug("Trying to reload: "+errorMessage);
                            pkf.set(P11ProviderHandler.this.getKeyStore(getP11Pwd(null)));
                            m_log.info("Reloaded: "+errorMessage);
                        }
                    }
                    setNextKeyUpdate(new Date().getTime()); // since all keys are now reloaded we should wait an whole interval for next key update
                    OCSPServletStandAloneSession.this.isNotReloadingP11Keys = true;
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
            if ( OCSPServletStandAloneSession.this.doNotStorePasswordsInMemory ) {
                m_log.info("Not possible to recover a lost HSM with no passowrd.");
                return;
            }
            if ( !OCSPServletStandAloneSession.this.isNotReloadingP11Keys ) {
                return;
            }
            OCSPServletStandAloneSession.this.isNotReloadingP11Keys = false;
            new Thread(new Reloader()).start();
        }
        /* (non-Javadoc)
         * @see org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.ProviderHandler#addKeyContainer(org.ejbca.ui.web.protocol.OCSPServletStandAloneSession.PrivateKeyContainer)
         */
        public void addKeyContainer(PrivateKeyContainer keyContainer) {
            this.sKeyContainer.add(keyContainer);
        }
    }
    /**
     * An object of this class is used to sign OCSP responses for certificates belonging to one CA.
     */
    private class SigningEntity {
        /**
         * The certificate chain with the CA of the signer on top.
         */
        final private List<X509Certificate> chain;
        /**
         * The signing key.
         */
        final private PrivateKeyContainer keyContainer;
        /**
         * The provider to be used when signing.
         */
        final private ProviderHandler providerHandler;
        /**
         * The object is ready to sign after this constructor has been called.
         * @param c Certificate chain with CA for which OCSP requests should be signed on top.
         * @param f The signing key.
         * @param ph The provider.
         */
        SigningEntity(List<X509Certificate> c, PrivateKeyContainer f, ProviderHandler ph) {
            this.chain = c;
            this.keyContainer = f;
            this.providerHandler = ph;
        }
        /**
         * Get certificate chain. With signing certificate on top.
         * @return The chain.
         */
        private X509Certificate[] getCertificateChain() {
            return getCertificateChain(this.keyContainer.getCertificate());
        }
        /**
         * Add certificate on top of certificate chain.
         * @param entityCert The certificate to be on top.
         * @return The certificate chain.
         */
        private X509Certificate[] getCertificateChain(final X509Certificate entityCert) {
            final List<X509Certificate> entityChain = new ArrayList<X509Certificate>(this.chain);
            if ( entityCert==null ) {
                m_log.error("CA "+this.chain.get(0).getSubjectDN()+" has no signer.");
                return null;
            }
            entityChain.add(0, entityCert);
            return entityChain.toArray(new X509Certificate[0]);
        }
        /**
         * Initiates key key renewal.
         * @param caid The EJBCA CA id for the CA.
         */
        void init(int caid) {
            this.providerHandler.addKeyContainer(this.keyContainer);
            this.keyContainer.init(this.chain, caid);
        }
        /**
         * Stops key renewal.
         */
        void shutDown() {
            this.keyContainer.destroy();
        }
        /**
         * Signs a OCSP response.
         * @param request The response to be signed.
         * @return The signed response.
         * @throws ExtendedCAServiceRequestException
         * @throws IllegalExtendedCAServiceRequestException
         */
        OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
            final String hsmErrorString = "HSM not functional";
            final String providerName = this.providerHandler.getProviderName();
            final long HSM_DOWN_ANSWER_TIME = 15000; 
            if ( providerName==null ) {
                synchronized(this) {
                    try {
                        this.wait(HSM_DOWN_ANSWER_TIME); // Wait here to prevent the client repeat the request right away. Some CPU power might be needed to recover the HSM.
                    } catch (InterruptedException e) {
                        throw new Error(e); //should never ever happen. The main thread should never be interrupted.
                    }
                }
                throw new ExtendedCAServiceRequestException(hsmErrorString+". Waited "+HSM_DOWN_ANSWER_TIME/1000+" seconds to throw the exception");
            }
            final PrivateKey privKey;
            final X509Certificate entityCert;
            try {
                entityCert = this.keyContainer.getCertificate();
                privKey = this.keyContainer.getKey(); // must be last.
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
                return OCSPUtil.createOCSPCAServiceResponse(request, privKey, providerName, getCertificateChain(entityCert));
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
            } finally {
                this.keyContainer.releaseKey();
            }
        }
        /**
         * Checks if the signer could be used.
         * @return True if OK.
         */
        boolean isOK() {
            try {
                return this.keyContainer.isOK();
            } catch (Exception e) {
                m_log.info("Exception thrown when accessing the private key: ", e);
                return false;
            }
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
    /**
     * Answers the OCSP request. The answer is assembled in a separate thread by an object of the class {@link SignerThread}.
     * @param caid EJBCA id for the CA.
     * @param request Object with for the request.
     * @return the response.
     * @throws ExtendedCAServiceRequestException
     * @throws ExtendedCAServiceNotActiveException
     * @throws IllegalExtendedCAServiceRequestException
     */
    OCSPCAServiceResponse extendedService(int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException {
        final Map<Integer, SigningEntity> map = this.signEntitycontainer.getSigningEntityMap();
        SigningEntity se = null;
        if ( map!=null ) {
            se = map.get(new Integer(caid));
            if ( se==null ) {
                if (m_log.isDebugEnabled()) {
                    m_log.debug("No key is available for caid=" + caid + " even though a valid certificate was present. Trying to use the default responder's key instead.");
                }
                se = map.get(new Integer(this.servlet.getCaid(null)));	// Use the key issued by the default responder ID instead
            }
        }
        if ( se==null ) {
            final ExtendedCAServiceNotActiveException e = new ExtendedCAServiceNotActiveException("No ocsp signing key for caid "+caid);
            synchronized(e) {
                try {
                    e.wait(10000); // calm down the client
                } catch (InterruptedException e1) {
                    throw new Error("Should never ever happend", e);
                }
            }
            throw e;
        }
        final SignerThread runnable = new SignerThread(se,request);
        final Thread thread = new Thread(runnable);
        thread.start();
        final OCSPCAServiceResponse result = runnable.getSignResult();
        thread.interrupt();
        return result;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#deactivate()
     */
    public boolean deactivate() throws Exception {
        this.slot.logoutFromSlotIfNoTokensActive();
        // should allways be active
        return true;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.P11Slot.P11SlotUser#isActive()
     */
    public boolean isActive() {
        return this.doNotStorePasswordsInMemory; // if not active it is possible to logout from the slot. if logged out you need password to login again.
    }
}
