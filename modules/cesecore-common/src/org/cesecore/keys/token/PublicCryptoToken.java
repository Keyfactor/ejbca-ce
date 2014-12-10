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
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;

/**
 * Just to be used for encryption (not decryption) and verifying (not signing)
 * by the public part of an asymmetric key.
 * 
 * @version $Id$
 */
public class PublicCryptoToken implements CryptoToken {

	private static final long serialVersionUID = 1L;
	private int id;
	private static final Logger log = Logger.getLogger(PublicCryptoToken.class);
	private PublicKey pk;
	private final static String providerName = "SunRsaSign";
	private String tokenName = "not available";

	@Override
	public void init(Properties properties, byte[] data, int _id)
			throws Exception {
		this.id = _id;
		if ( data==null || data.length<1 ) {
			final String msg = "No data for public key in token with id: "+this.id;
			log.error(msg);
			throw new Exception( msg );
		}
		this.pk = getPublicKey(data);
		if ( this.pk==null ) {
			final String msg = "Not possible to initiate public key id: "+this.id;
			log.error(msg);
			throw new Exception( msg );
		}
	}

	private static PublicKey getPublicKey(final byte data[]) {
		try {
			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(data));
		} catch (InvalidKeySpecException e) {
			log.debug("Not an X509 key.", e);
		} catch (NoSuchAlgorithmException e) {
			log.debug("No RSA key factory available. Try to read key from cert instead.", e);
		}
		try {
			return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(data)).getPublicKey();
		} catch (CertificateException e) {
			log.debug("Public key data is not a certificate.", e);
		}
		return null; // no more formats to try
	}
	@Override
	public int getId() {
		return this.id;
	}

	@Override
	public void activate(char[] authenticationcode)
			throws CryptoTokenOfflineException,
			CryptoTokenAuthenticationFailedException {
		// no private key to activate
	}

	@Override
	public void deactivate() {
		// no private key to deactivate
	}

    @Override
    public boolean isAliasUsed(String alias) {
        try {
            return (getPublicKey(alias) != null);
        } catch (CryptoTokenOfflineException e) {
            // This will never happen
            return false;
        }
    }

	@Override
	public PrivateKey getPrivateKey(String alias)
			throws CryptoTokenOfflineException {
		// no private key for this token
		return null;
	}

	@Override
	public PublicKey getPublicKey(String alias)
			throws CryptoTokenOfflineException {
		return this.pk;
	}

	@Override
	public Key getKey(String alias) throws CryptoTokenOfflineException {
		// no symmetric key for this token.
		return null;
	}

	@Override
	public void deleteEntry(String alias)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, CryptoTokenOfflineException {
		// static do nothing
	}

	@Override
	public void generateKeyPair(String keySpec, String alias)
			throws InvalidAlgorithmParameterException,
			CryptoTokenOfflineException {
		// static do nothing
	}

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias) throws InvalidAlgorithmParameterException, CertificateException,
            IOException, CryptoTokenOfflineException {
        // static do nothing
    }

	@Override
	public void generateKey(String algorithm, int keysize, String alias)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			KeyStoreException, CryptoTokenOfflineException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			SignatureException, CertificateException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException {
		// static do nothing
	}

	@Override
	public String getSignProviderName() {
		return providerName;
	}

	@Override
	public String getEncProviderName() {
		return providerName;
	}

	@Override
	public void reset() {
		// do nothing
	}

	@Override
	public int getTokenStatus() {
		if ( this.pk==null ) {
			return CryptoToken.STATUS_OFFLINE;
		}
		return CryptoToken.STATUS_ACTIVE;
	}

	@Override
	public Properties getProperties() {
		return new Properties();
	}

	@Override
	public void setProperties(Properties properties) {
		// do nothing
	}

	@Override
	public byte[] getTokenData() {
		return this.pk.getEncoded();
	}

	@Override
	public byte[] extractKey(String privKeyTransform,
			String encryptionKeyAlias, String privateKeyAlias)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			NoSuchProviderException, InvalidKeyException,
			IllegalBlockSizeException, CryptoTokenOfflineException,
			PrivateKeyNotExtractableException,
			InvalidAlgorithmParameterException {
		return null;
	}

	@Override
	public byte[] extractKey(String privKeyTransform,
			AlgorithmParameterSpec spec, String encryptionKeyAlias,
			String privateKeyAlias) throws NoSuchAlgorithmException,
			NoSuchPaddingException, NoSuchProviderException,
			InvalidKeyException, IllegalBlockSizeException,
			CryptoTokenOfflineException, PrivateKeyNotExtractableException,
			InvalidAlgorithmParameterException {
		return null;
	}

	@Override
	public boolean doPermitExtractablePrivateKey() {
		return false;
	}

    @Override
    public List<String> getAliases() {
        return Arrays.asList("dummy");
    }

	@Override
	public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
		if ( chain==null || chain.length<1 ) {
			return;
		}
		this.pk = chain[0].getPublicKey();
	}

    @Override
    public boolean isAutoActivationPinPresent() {
        return BaseCryptoToken.getAutoActivatePin(getProperties()) != null;
    }
    
    @Override
    public void testKeyPair(final String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        // be positive.. NOT!
        throw new CryptoTokenOfflineException("Implementation does not contain any private keys to use for test.");
    }

    @Override
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
        // be positive.. NOT!
        throw new InvalidKeyException("Implementation does not contain any private keys to use for test.");
    }

    @Override
    public String getTokenName() {
        return tokenName;
    }

    @Override
    public void setTokenName(final String tokenName) {
        this.tokenName = tokenName;
    }

}
