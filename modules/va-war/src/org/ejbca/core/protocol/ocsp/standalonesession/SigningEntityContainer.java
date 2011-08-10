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

package org.ejbca.core.protocol.ocsp.standalonesession;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.ui.web.protocol.OCSPServletStandAlone;

/**
 * Holds a {@link SigningEntity} for each CA that the responder is capable of signing a response for.
 * 
 * @author primelars
 * @version  $Id$
 */
class  SigningEntityContainer {
    /**
     * Log object.
     */
    static private final Logger m_log = Logger.getLogger(SigningEntityContainer.class);
    /**
     * Internal localization of logs and errors
     */
    static private final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    /**
     * The data of the session.
     */
    private final SessionData sessionData;
    /**
     * @param standAloneSession
     */
    SigningEntityContainer(SessionData _sessionData) {
        this.sessionData = _sessionData;
    }
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
     * If it is {@link #loadPrivateKeys2(AuthenticationToken, String)} is called after calculating time fot new update.
     * @param adm Administrator to be used when getting the certificate chain from the DB.
     * @param password This password is only set if passwords should not be stored in memory.
     * @throws Exception
     */
    void loadPrivateKeys(final AuthenticationToken adm, final String password ) throws Exception {
        try {
            this.mutex.getMutex();
            final long currentTime = new Date().getTime();
            // We will only load private keys if the cache time has run out
            if ( password==null && (
                    this.updating || this.lastTryOfKeyReload+10000>currentTime || !this.sessionData.isNotReloadingP11Keys ||
                    (this.signEntityMap!=null && this.signEntityMap.size()>0 && this.sessionData.data.mKeysValidTo>currentTime)
            ) ) {
                return;
            }
            this.sessionData.setNextKeyUpdate(currentTime);// set next time for key loading
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
    private void loadPrivateKeys2(AuthenticationToken adm, String password ) throws Exception {
        if ( this.signEntityMap!=null ){
            Collection<SigningEntity> values=this.signEntityMap.values();
            if ( values!=null ) {
                final Iterator<SigningEntity> i = values.iterator();
                while( i.hasNext() ) {
                    i.next().shutDown();
                }
            }
        }
        if ( this.cardKeys==null && this.sessionData.hardTokenClassName!=null && this.sessionData.hardTokenClassName.length()>0 ) {
            final String tmpPassword = password!=null ? password : this.sessionData.cardPassword;
            if ( tmpPassword!=null  ) {
                try {
                    this.cardKeys = (CardKeys)OCSPServletStandAlone.class.getClassLoader().loadClass(this.sessionData.hardTokenClassName).newInstance();
                    this.cardKeys.autenticate(tmpPassword);
                } catch( ClassNotFoundException e) {
                    m_log.info(intres.getLocalizedMessage("ocsp.classnotfound", this.sessionData.hardTokenClassName));
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
        final File dir = this.sessionData.mKeystoreDirectoryName!=null ? new File(this.sessionData.mKeystoreDirectoryName) : null;
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
                final String p11name = this.sessionData.slot!=null && this.sessionData.slot.getProvider()!=null ? this.sessionData.slot.getProvider().getName() : null;
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
    private boolean loadFromP11HSM(AuthenticationToken adm, Map<Integer, SigningEntity> newSignEntity,
                                   String password) {
        final PasswordProtection pwp = this.sessionData.getP11Pwd(password);
        if ( !checkPassword( pwp, OcspConfiguration.P11_PASSWORD) ) {
            return false;
        }
        if ( this.sessionData.slot==null ) {
            m_log.debug("no shared library");
            return false;           
        }
        this.sessionData.slot.reset();
        try {
            final P11ProviderHandler providerHandler = new P11ProviderHandler(this.sessionData);
            loadFromKeyStore(adm, providerHandler.getKeyStore(pwp), null,
                             this.sessionData.slot.toString(),
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
    private boolean loadFromSWKeyStore(AuthenticationToken adm, String fileName, HashMap<Integer, SigningEntity> newSignEntity,
                                       String password) {
        try {
            final String storePassword = this.sessionData.mStorePassword!=null ? this.sessionData.mStorePassword : password;
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
            final String keyPassword = this.sessionData.mKeyPassword!=null ? this.sessionData.mKeyPassword : password;
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
    private void loadFromKeyStore(AuthenticationToken adm, KeyStore keyStore, String keyPassword,
                                  String errorComment, ProviderHandler providerHandler,
                                  Map<Integer, SigningEntity> newSignEntity, String fileName) throws KeyStoreException {
        final Enumeration<String> eAlias = keyStore.aliases();
        while( eAlias.hasMoreElements() ) {
            final String alias = eAlias.nextElement();
            if ( this.sessionData.keyAlias!=null && !this.sessionData.keyAlias.contains(alias) ) {
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
                final PrivateKeyContainer pkf = new PrivateKeyContainerKeyStore( this.sessionData, alias, keyPassword!=null ? keyPassword.toCharArray() : null,
                                                                                 keyStore, cert, providerHandler.getProviderName(), fileName );
                final PrivateKey key = pkf.getKey();
                if ( key==null ) {
                    m_log.debug("Key not available. Not adding signer entity for: "+pkf.getCertificate().getSubjectDN()+"', keystore alias '"+alias+"'");
                    continue;
                }
                try {
                	KeyTools.testKey(key, pkf.getCertificate().getPublicKey(), providerHandler.getProviderName());
                    m_log.debug("Adding sign entity for '"+pkf.getCertificate().getSubjectDN()+"', keystore alias '"+alias+"'");
                    putSignEntity(pkf, pkf.getCertificate(), adm, providerHandler, newSignEntity);
                } catch (InvalidKeyException e) {
                	// thrown by testKey
                    m_log.debug("Key not working. Not adding signer entity for: "+pkf.getCertificate().getSubjectDN()+"', keystore alias '"+alias+"'. Error comment '"+errorComment+"'. Message '"+e.getMessage());
                    continue;                	
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
    private List<X509Certificate> getCertificateChain(X509Certificate cert, AuthenticationToken adm) {
        String issuerDN = CertTools.getIssuerDN(cert);
        final CertificateStatus status = this.sessionData.data.certificateStoreSession.getStatus(issuerDN, CertTools.getSerialNumber(cert));
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
            final X509Certificate target = this.sessionData.data.m_caCertCache.findLatestBySubjectDN(HashID.getFromIssuerDN(current));
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
    private boolean putSignEntity( PrivateKeyContainer keyContainer, X509Certificate cert, AuthenticationToken adm, ProviderHandler providerHandler,
                                   final Map<Integer, SigningEntity> newSignEntitys) {
        if ( keyContainer==null || cert==null ) {
            return false;
        }
        final List<X509Certificate> chain = getCertificateChain(cert, adm);
        if ( chain==null || chain.size()<1 ) {
            return false;
        }
        final Integer caid = new Integer(this.sessionData.data.getCaid(chain.get(0)));
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
    private boolean putSignEntityCard( Certificate cert, AuthenticationToken adm,
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
    private void loadFromKeyCards(AuthenticationToken adm, String fileName, Map<Integer, SigningEntity> newSignEntity) {
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