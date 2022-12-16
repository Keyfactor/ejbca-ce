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

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Assert;
import org.junit.Test;

/**
 * Stand alone test of CachingKeyStoreWrapper.
 * 
 * @version $Id$
 */
public class CachingKeyStoreWrapperTest {

    public CachingKeyStoreWrapperTest() {
        CryptoProviderTools.installBCProvider();
    }

    private static final String ALIAS = "alias";
    private static final char[] PASSWORD = "foo123".toCharArray();

    @Test
    public void testGenerateUseDeleteNoCache() throws Exception {
        testGenerateUseDelete(false);
    }

    @Test
    public void testGenerateUseDeleteCache() throws Exception {
        testGenerateUseDelete(true);
    }

    private void testGenerateUseDelete(final boolean cache) throws Exception {
        final KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        final CachingKeyStoreWrapper cachingKeyStoreWrapper = new CachingKeyStoreWrapper(keyStore, cache);
        testGenerate(cachingKeyStoreWrapper, ALIAS);
        testUse(cachingKeyStoreWrapper, ALIAS);
        testRemove(cachingKeyStoreWrapper, ALIAS);
    }

    @Test
    public void testPersistLoadNoCache() throws Exception {
        testPersistLoad(false);
    }

    @Test
    public void testPersistLoadCache() throws Exception {
        testPersistLoad(true);
    }

    private void testPersistLoad(final boolean cache) throws Exception {
        // Create a key store with some content
        final KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        final CachingKeyStoreWrapper cachingKeyStoreWrapper = new CachingKeyStoreWrapper(keyStore, cache);
        testGenerate(cachingKeyStoreWrapper, ALIAS);
        // "Persist" and load it back from storage
        final ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
        cachingKeyStoreWrapper.store(baos2, PASSWORD);
        final KeyStore keyStore2 = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore2.load(new ByteArrayInputStream(baos2.toByteArray()), PASSWORD);
        // Test loaded key store
        final CachingKeyStoreWrapper cachingKeyStoreWrapper2 = new CachingKeyStoreWrapper(keyStore2, cache);
        testUse(cachingKeyStoreWrapper2, ALIAS);
        // "Persist" and load it back from storage
        final ByteArrayOutputStream baos3 = new ByteArrayOutputStream();
        cachingKeyStoreWrapper2.store(baos3, PASSWORD);
        final KeyStore keyStore3 = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore3.load(new ByteArrayInputStream(baos3.toByteArray()), PASSWORD);
        // Test loaded key store
        final CachingKeyStoreWrapper cachingKeyStoreWrapper3 = new CachingKeyStoreWrapper(keyStore3, cache);
        testRemove(cachingKeyStoreWrapper3, ALIAS);
    }

    private void testGenerate(final CachingKeyStoreWrapper cachingKeyStoreWrapper, final String alias) throws Exception {
        final int aliasCountBefore = getAliasCount(cachingKeyStoreWrapper);
        // Generate a key pair
        final KeyStoreTools keyStoreTools = new KeyStoreTools(cachingKeyStoreWrapper, cachingKeyStoreWrapper.getProvider().getName());
        keyStoreTools.generateKeyPair("secp256r1", alias);
        // Verify that key store contains the key pair
        Assert.assertEquals("Number of aliases should have increased by 1 after generation.", aliasCountBefore+1, getAliasCount(cachingKeyStoreWrapper));
        Assert.assertTrue("Generated key pair alias was not found.", isContainsAlias(cachingKeyStoreWrapper, alias));
        final Key key = cachingKeyStoreWrapper.getKey(alias, null);
        Assert.assertNotNull("No private key for generated key pair could be found.", key);
        Assert.assertTrue(key instanceof PrivateKey);
        final Certificate certificate = cachingKeyStoreWrapper.getCertificate(alias);
        Assert.assertNotNull("No certificate for generated key pair could be found.", certificate);
    }
    
    private void testUse(final CachingKeyStoreWrapper cachingKeyStoreWrapper, final String alias) throws Exception {
        final Key key = cachingKeyStoreWrapper.getKey(alias, null);
        final Certificate certificate = cachingKeyStoreWrapper.getCertificate(alias);
        // Verify that key pair from the key store is usable
        KeyTools.testKey((PrivateKey)key, certificate.getPublicKey(), cachingKeyStoreWrapper.getProvider().getName());
    }

    private void testRemove(final CachingKeyStoreWrapper cachingKeyStoreWrapper, final String alias) throws Exception {
        final int aliasCountBefore = getAliasCount(cachingKeyStoreWrapper);
        // Remove the key pair
        final KeyStoreTools keyStoreTools = new KeyStoreTools(cachingKeyStoreWrapper, cachingKeyStoreWrapper.getProvider().getName());
        keyStoreTools.deleteEntry(alias);
        Assert.assertEquals("Number of aliases should have decreased by 1 after removal.", aliasCountBefore-1, getAliasCount(cachingKeyStoreWrapper));
        Assert.assertFalse("Alias of removed key pair still exist.", isContainsAlias(cachingKeyStoreWrapper, alias));
    }

    /** @return the count of aliases the wrapped key store claims to exist */
    private int getAliasCount(final CachingKeyStoreWrapper cachingKeyStoreWrapper) throws KeyStoreException {
        final Enumeration<String> aliasEnumeration = cachingKeyStoreWrapper.aliases();
        int aliasCount = 0;
        while (aliasEnumeration.hasMoreElements()) {
            aliasEnumeration.nextElement();
            aliasCount++;
        }
        return aliasCount;
    }

    /** @return true if the wrapped key store claims the alias exist */
    private boolean isContainsAlias(final CachingKeyStoreWrapper cachingKeyStoreWrapper, final String alias) throws KeyStoreException {
        final Enumeration<String> aliasEnumeration = cachingKeyStoreWrapper.aliases();
        while (aliasEnumeration.hasMoreElements()) {
            final String currentAlias = aliasEnumeration.nextElement();
            if (alias.equals(currentAlias)) {
                return true;
            }
        }
        return false;
    }
}
