/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Vector;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

/**
 * Wrapper of a Java KeyStore to speed up key operations by caching key references.
 * 
 * Aliases and certificates are read when the class is initiated from the underlying key store.
 * PrivateKey and SecretKey objects are read and cached when the key specific protection is available (when used).
 * 
 * @version $Id$
 */
public class CachingKeyStoreWrapper {
    /** Similar to Java's KeyStore.Entry */
    private static final Logger log = Logger.getLogger(CachingKeyStoreWrapper.class);
    private final ReentrantLock updateLock = new ReentrantLock(false);
    private final KeyStore keyStore;
    private final KeyStoreCache keyStoreCache;
    private class KeyStoreMapEntry {
        public final Key key;
        public final Certificate[] certificateChain;
        public final boolean isTrusted;
        public KeyStoreMapEntry(final String alias, final KeyStore keyStore) throws KeyStoreException {
            if (keyStore.isCertificateEntry(alias)) {
                // See if there is a TrustedCertificateEntry instead
                final Certificate certificate = keyStore.getCertificate(alias);
                this.certificateChain = new Certificate[] { certificate };
                this.key = null;
                this.isTrusted = true;
                return;
            }
            this.isTrusted = false;
            this.certificateChain = keyStore.getCertificateChain(alias);
            Key tmpKey;
            try {
                tmpKey = keyStore.getKey(alias, null);
            } catch (KeyStoreException e) {
                throw e;
            } catch (Exception e) {
                tmpKey = null;
            }
            this.key = tmpKey;
        }
        public KeyStoreMapEntry(
                final String alias, final KeyStore keyStore, final char password[],
                final KeyStoreMapEntry oldEntry)
                        throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
            assert !oldEntry.isTrusted;
            this.isTrusted = false;
            this.certificateChain = oldEntry.certificateChain;
            this.key = keyStore.getKey(alias, password);
        }
        public KeyStoreMapEntry( final Certificate certificate ) {
            this.key = null;
            this.isTrusted = true;
            this.certificateChain = new Certificate[] { certificate };
        }
        public KeyStoreMapEntry( final Certificate[] chain, final Key k ) {
            this.key = k;
            this.isTrusted = false;
            this.certificateChain = chain;
        }
        public KeyStoreMapEntry(
                final String alias, final ProtectionParameter protection,
                final KeyStore keyStore )
                        throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
            this(keyStore.getEntry(alias, protection));
        }
        public KeyStoreMapEntry( final Entry entry ) {
            if ( entry instanceof PrivateKeyEntry ) {
                this.key = ((PrivateKeyEntry) entry).getPrivateKey();
                this.certificateChain = ((PrivateKeyEntry) entry).getCertificateChain();
                this.isTrusted = false;
                return;
            }
            if ( entry instanceof SecretKeyEntry ) {
                this.key =((SecretKeyEntry) entry).getSecretKey();
                this.certificateChain = null;
                this.isTrusted = false;
                return;
            }
            if ( entry instanceof TrustedCertificateEntry ) {
                this.key = null;
                this.certificateChain = new Certificate[] { ((TrustedCertificateEntry) entry).getTrustedCertificate() };
                this.isTrusted = true;
                return;
            }
            throw new Error("It should not be possible to reach this point!");
        }
        public Entry getEntry() {
            if ( this.isTrusted  ) {
                assert this.certificateChain!=null;
                // No constructor puts more than one certificate in the chain when trusted.
                assert this.certificateChain.length==1;
                return new TrustedCertificateEntry(this.certificateChain[0]);
            }
            assert this.key!=null;
            if ( this.certificateChain!=null ) {
                return new PrivateKeyEntry((PrivateKey) this.key, this.certificateChain);
            }
            return new SecretKeyEntry((SecretKey) this.key);
        }
    }

    private class KeyStoreCache {
        private HashMap<String, KeyStoreMapEntry> cache;

        @SuppressWarnings("synthetic-access")
        public KeyStoreCache(final KeyStore keyStore) throws KeyStoreException {
            this.cache = new HashMap<>();
            // Load the whole public KeyStore content (aliases and certificate) into the cache
            final Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                this.cache.put(fixBadUTF8(alias), new KeyStoreMapEntry(alias, keyStore));
                if (log.isDebugEnabled()) {
                    log.debug("KeyStore has alias: " + alias);
                }
            }
        }
        public void addEntry(final String alias, final  KeyStoreMapEntry newEntry) {
            final HashMap<String, KeyStoreMapEntry> clone = new HashMap<>(this.cache);
            clone.put(alias, newEntry);
            this.cache = clone;
        }
        public void removeEntry(final String alias) {
            final HashMap<String, KeyStoreMapEntry> clone = new HashMap<>(this.cache);
            clone.remove(alias);
            this.cache = clone;
        }
        public KeyStoreMapEntry get(final String alias) {
            return this.cache.get(alias);
        }
        public Enumeration<String> getAliases() {
            return new Vector<>(this.cache.keySet()).elements();
        }
    }

    private static boolean isSunP11( final KeyStore keyStore ) {
        return keyStore.getProvider().getName().indexOf("SunPKCS11")==0;
    }

    /**
     * The Sun p11 implementation of the {@link KeyStore} returns aliases that
     * are badly encoded. This method fix this encoding.
     * @param orig a badly encoded alias.
     * @return a correct encoded alias.
     */
    private String fixBadUTF8(final String orig) {
        if ( !isSunP11(this.keyStore) ) {
            return orig;
        }
        try {
            final byte bvIn[] = orig.getBytes("UTF-16BE");
            final byte bvOut[] = new byte[bvIn.length/2];
            for ( int i=1; i<bvIn.length; i += 2) {
                bvOut[i/2] = (byte)(bvIn[i]&0xff);
            }
            return new String(bvOut, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-16BE and UTF-8 must be implemented for all JREs.");
        }
    }

    /**
     * When deleting a key in the sun p11 implementation of {@link KeyStore} the
     * alias {@link String} must be altered due to an implementation bug.
     * @param orig the alias
     * @return modified alias to suit the sun p11.
     */
    private String makeBadUTF8(final String orig) {
        if ( !isSunP11(this.keyStore) ) {
            return orig;
        }
        try {
            final byte bvIn[] = orig.getBytes("UTF-8");
            final byte bvOut[] = new byte[bvIn.length*2];
            for ( int i=0; i<bvIn.length; i += 1) {
                bvOut[i*2] = 0;
                bvOut[i*2+1] = (byte)(bvIn[i]&0xff);
            }
            return new String(bvOut, "UTF-16BE");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-16BE and UTF-8 must be implemented for all JREs.");
        }
    }

    @Deprecated // Should only be used from OcspResponseGeneratorSessionBean.adhocUpgradeFromPre60
    public KeyStore getKeyStore() { return this.keyStore; }
    
    /**
     * Wrap the key store object with optional caching of all entries.
     * 
     * @param keyStore the key store to wrap
     * @param cachingEnabled true will cache a list of all aliases, certificates and lazily cache private and secret keys when accessed
     * @throws KeyStoreException if the underlying key store cannot be accessed
     */
    public CachingKeyStoreWrapper(final KeyStore keyStore, final boolean cachingEnabled) throws KeyStoreException {
        this.keyStore = keyStore;
        if (log.isDebugEnabled()) {
            log.debug("cachingEnabled: " + cachingEnabled);
        }
        if (cachingEnabled) {
            this.keyStoreCache = new KeyStoreCache(keyStore);
        } else {
            this.keyStoreCache = null;
        }
    }

    /** @see java.security.KeyStore#getCertificate(String) */
    public Certificate getCertificate(final String alias) throws KeyStoreException {
        if (this.keyStoreCache==null) {
            return this.keyStore.getCertificate(alias);
        }
        final KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        if (keyStoreMapEntry==null) {
            return null;
        }
        if (keyStoreMapEntry.certificateChain==null || keyStoreMapEntry.certificateChain.length==0) {
            return null;
        }
        return keyStoreMapEntry.certificateChain[0];
    }

    /** @see java.security.KeyStore#setCertificateEntry(String, Certificate) */
    public void setCertificateEntry(final String alias, final Certificate certificate) throws KeyStoreException {
        // Update the TrustedCertificateEntry in the real key store
        this.keyStore.setCertificateEntry(alias, certificate);
        if (this.keyStoreCache==null) {
            return;
        }
        this.updateLock.lock();
        try {
            this.keyStoreCache.addEntry(alias, new KeyStoreMapEntry(certificate));
        } finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug("Updated certificate entry in cache for alias: " + alias);
        }
    }

    /** @see java.security.KeyStore#aliases() */
    public Enumeration<String> aliases() throws KeyStoreException {
        if (this.keyStoreCache==null) {
            return this.keyStore.aliases();
        }
        return this.keyStoreCache.getAliases();
    }

    /** @see java.security.KeyStore#store(OutputStream, char[]) */
    public void store(final OutputStream outputStream, final char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.store(outputStream, password);
    }

    /** @see java.security.KeyStore#setKeyEntry(String, Key, char[], Certificate[]) */
    public void setKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain) throws KeyStoreException {
        // Removal of old key is only needed for sun-p11 with none ASCII chars in the alias.
        // But it makes no harm to always do it and it should be fast.
        // If not done the entry will not be stored correctly in the p11 KeyStore.
        this.keyStore.deleteEntry(makeBadUTF8(alias));
        this.keyStore.setKeyEntry(alias, key, password, chain);
        if (this.keyStoreCache==null) {
            return;
        }
        this.updateLock.lock();
        try {
            final KeyStoreMapEntry keyStoreMapEntry = new KeyStoreMapEntry(chain,key);
            this.keyStoreCache.addEntry(alias, keyStoreMapEntry);
        } finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug("Updated key entry in cache for alias: " + alias);
        }
    }

    /** @see java.security.KeyStore#deleteEntry(String) */
    public void deleteEntry(final String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(makeBadUTF8(alias));
        if (this.keyStoreCache==null) {
            return;
        }
        this.updateLock.lock();
        try {
            this.keyStoreCache.removeEntry(alias);
        } finally {
            this.updateLock.unlock();
        }
        if (log.isDebugEnabled()) {
            log.debug("Removed entry from cache for alias: " + alias);
        }
    }

    /** @see java.security.KeyStore#getEntry(String, ProtectionParameter) */
    public Entry getEntry(final String alias, final ProtectionParameter protParam) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        if (this.keyStoreCache==null) {
            return this.keyStore.getEntry(alias, protParam);
        }
        {
            final KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
            if (keyStoreMapEntry==null) {
                // If the alias exists it has a KeyStoreMapEntry. No need to query the key store here.
                return null;
            }
            if ( keyStoreMapEntry.isTrusted || keyStoreMapEntry.key!=null ) {
                return keyStoreMapEntry.getEntry();
            }
        }
        this.updateLock.lock();
        try {
            // Check if another thread has retrieved the key while we waited for the lock
            final KeyStoreMapEntry afterWaitEntry = this.keyStoreCache.get(alias);
            if ( afterWaitEntry.isTrusted || afterWaitEntry.key!=null ) {
                return afterWaitEntry.getEntry();
            }
            final KeyStoreMapEntry newEntry = new KeyStoreMapEntry(alias, protParam, this.keyStore);
            this.keyStoreCache.addEntry(alias, newEntry);
            return newEntry.getEntry();
        } finally {
            this.updateLock.unlock();
        }
    }

    /** @see java.security.KeyStore#setEntry(String, Entry, ProtectionParameter) */
    public void setEntry(final String alias, final Entry entry, final ProtectionParameter protParam) throws KeyStoreException {
        this.keyStore.setEntry(alias, entry, protParam);
        if (this.keyStoreCache==null) {
            return;
        }
        this.updateLock.lock();
        try {
            final KeyStoreMapEntry keyStoreMapEntry = new KeyStoreMapEntry(entry);
            this.keyStoreCache.addEntry(alias, keyStoreMapEntry);
        } finally {
            this.updateLock.unlock();
        }
    }

    /** @see java.security.KeyStore#getProvider() */
    public Provider getProvider() {
        return this.keyStore.getProvider();
    }

    /** @see java.security.KeyStore#getKey(String, char[]) */
    public Key getKey(final String alias, final char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if (this.keyStoreCache==null) {
            return this.keyStore.getKey(alias, password);
        }
        {
            final KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
            if (keyStoreMapEntry==null) {
                // If the alias exists it has a KeyStoreMapEntry. No need to query the key store here.
                return null;
            }
            if ( keyStoreMapEntry.isTrusted || keyStoreMapEntry.key!=null ) {
                // There is no key if it is a trusted Entry.
                return keyStoreMapEntry.key;
            }
        }
        this.updateLock.lock();
        try {
            // Check if another thread has retrieved the key while we waited for the lock
            final KeyStoreMapEntry entryAfterWait = this.keyStoreCache.get(alias);
            if ( entryAfterWait.isTrusted || entryAfterWait.key!=null ) {
                return entryAfterWait.key;
            }
            final KeyStoreMapEntry newEntry = new KeyStoreMapEntry(alias, this.keyStore, password, entryAfterWait);
            this.keyStoreCache.addEntry(alias, newEntry);
            if (log.isDebugEnabled()) {
                log.debug("Caching key for alias: " + alias);
            }
            return newEntry.key;
        } finally {
            this.updateLock.unlock();
        }
    }

    /** @see java.security.KeyStore#isKeyEntry(String) */
    public boolean isKeyEntry(final String alias ) throws KeyStoreException {
        if (this.keyStoreCache==null) {
            return this.keyStore.isKeyEntry(alias);
        }
        final KeyStoreMapEntry keyStoreMapEntry = this.keyStoreCache.get(alias);
        return keyStoreMapEntry!=null && !keyStoreMapEntry.isTrusted;
    }

    /** @see java.security.KeyStore#getCertificateChain(String) */
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        if (this.keyStoreCache==null) {
            return this.keyStore.getCertificateChain(alias);
        }
        final KeyStoreMapEntry entry = this.keyStoreCache.get(alias);
        return entry!=null ? entry.certificateChain : null;
    }
}
