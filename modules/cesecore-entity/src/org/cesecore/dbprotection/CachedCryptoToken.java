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
package org.cesecore.dbprotection;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Wrapper for a CryptoToken that caches references to private and secret keys.
 * Used to speed up database integrity protection, where the key should always
 * be available.
 *
 * @version $Id$
 *
 */
public class CachedCryptoToken implements CryptoToken {

    private static final long serialVersionUID = 1L;

    private final CryptoToken wrappedCryptoToken;
    private Key cachedKey = null;
    private PrivateKey cachedPrivateKey = null;
    private String cachedSignProviderName = null;

    public CachedCryptoToken(final CryptoToken wrappedCryptoToken) {
        this.wrappedCryptoToken = wrappedCryptoToken;
    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        wrappedCryptoToken.activate(authenticationcode);
    }

    @Override
    public void deactivate() {
        wrappedCryptoToken.deactivate();
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {
        wrappedCryptoToken.deleteEntry(alias);
    }

    @Override
    public boolean doPermitExtractablePrivateKey() {
        return wrappedCryptoToken.doPermitExtractablePrivateKey();
    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException,
            KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException,
            SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException {
        wrappedCryptoToken.generateKey(algorithm, keysize, alias);
    }

    @Override
    public void generateKeyPair(String keySpec, String alias) throws InvalidAlgorithmParameterException,
            CryptoTokenOfflineException {
        wrappedCryptoToken.generateKeyPair(keySpec, alias);
    }

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias) throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException {
        wrappedCryptoToken.generateKeyPair(spec, alias);
    }

    @Override
    public String getEncProviderName() {
        return wrappedCryptoToken.getEncProviderName();
    }

    @Override
    public int getId() {
        return wrappedCryptoToken.getId();
    }

    @Override
    public String getTokenName() {
        return wrappedCryptoToken.getTokenName();
    }

    @Override
    public void setTokenName(final String tokenName) {
        wrappedCryptoToken.setTokenName(tokenName);
    }

    @Override
    public boolean isAliasUsed(String alias) {
        return wrappedCryptoToken.isAliasUsed(alias);
    }
    
    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        if (cachedKey==null) {
            cachedKey = wrappedCryptoToken.getKey(alias);
        }
        return cachedKey;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        if (cachedPrivateKey==null) {
            cachedPrivateKey = wrappedCryptoToken.getPrivateKey(alias);
        }
        return cachedPrivateKey;
    }

    @Override
    public Properties getProperties() {
        return wrappedCryptoToken.getProperties();
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        return wrappedCryptoToken.getPublicKey(alias);
    }

    @Override
    public String getSignProviderName() {
        if (cachedSignProviderName==null) {
            cachedSignProviderName = wrappedCryptoToken.getSignProviderName();
        }
        return cachedSignProviderName;
    }

    @Override
    public byte[] getTokenData() {
        return wrappedCryptoToken.getTokenData();
    }

    @Override
    public int getTokenStatus() {
        return wrappedCryptoToken.getTokenStatus();
    }

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
        wrappedCryptoToken.init(properties, data, id);
    }

    @Override
    public void reset() {
        wrappedCryptoToken.reset();
    }

    @Override
    public void setProperties(Properties properties) {
        wrappedCryptoToken.setProperties(properties);
    }

    @Override
    public void testKeyPair(final String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        wrappedCryptoToken.testKeyPair(alias);
    }
    @Override
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
        wrappedCryptoToken.testKeyPair(alias, publicKey, privateKey);
    }

    @Override
    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        return wrappedCryptoToken.getAliases();
    }

    @Override
    public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
        wrappedCryptoToken.storeKey(alias, key, chain, password);
        
    }

    @Override
    public boolean isAutoActivationPinPresent() {
        return wrappedCryptoToken.isAutoActivationPinPresent();
    }
}
