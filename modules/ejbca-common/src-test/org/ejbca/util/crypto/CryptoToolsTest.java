/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

/**
 * This class contains unit tests for the CryptoTools class.
 */
public class CryptoToolsTest {

    @Test
    public void testExtractSaltFromPasswordHash() {
        //Firstly, generate a hash.
        final String password = "greenunicornisfine";
        final String salt = BCrypt.gensalt(1);
        final String passwordHash = BCrypt.hashpw(password, salt);
        
        String extractedSalt = CryptoTools.extractSaltFromPasswordHash(passwordHash);
        assertEquals(salt, extractedSalt);
    }
    
    /** Test that we can generate and serialize/deserialize a key pair */
    @Test
    public void testKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ClassNotFoundException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        keygen.initialize(1024);
        KeyPair keys = keygen.generateKeyPair();
        byte[] encodedPublicKey = keys.getPublic().getEncoded();
        assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey", keys.getPublic().getClass().getName());
        assertEquals("X.509", keys.getPublic().getFormat());
        assertEquals("RSA", keys.getPublic().getAlgorithm());
        assertNotNull("Encoded public key should not be null", encodedPublicKey);
        byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
        assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey", keys.getPrivate().getClass().getName());
        assertEquals("PKCS#8", keys.getPrivate().getFormat());
        assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(baos);
        os.writeObject(keys);
        byte[] output = baos.toByteArray();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(output));
        Object o = ois.readObject();
        KeyPair keysSerialized = (KeyPair)o;
        encodedPublicKey = keysSerialized.getPublic().getEncoded();
        assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey", keys.getPublic().getClass().getName());
        assertEquals("X.509", keys.getPublic().getFormat());
        assertEquals("RSA", keys.getPublic().getAlgorithm());
        assertNotNull("Encoded public key should not be null", encodedPublicKey);
        encodedPrivateKey = keysSerialized.getPrivate().getEncoded();
        assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey", keys.getPrivate().getClass().getName());
        assertEquals("PKCS#8", keys.getPrivate().getFormat());
        assertNotNull("Encoded private key should not be null", encodedPrivateKey);
    }
    
    /** Test that we can encrypt and decrypt a KeyPair */
    @Test
    public void testEncryptDecryptKeyPair() throws NoSuchSlotException, InvalidAlgorithmParameterException, CryptoTokenOfflineException, IOException, InvalidKeyException {
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), new Properties(), null, 111, "Soft CryptoToken");
        final String alias = "alias";
        // key pair to encrypt decrypt keys
        cryptoToken.generateKeyPair(KeyGenParams.builder("1024").build(), alias);
        {
            final KeyPair keypair = KeyTools.genKeys("1024",  AlgorithmConstants.KEYALGORITHM_RSA);
            byte[] encryptedBytes = CryptoTools.encryptKeys(cryptoToken, alias, keypair);
            assertNotNull("Encrypted key pair should not be null", encryptedBytes);
            final KeyPair keys = CryptoTools.decryptKeys(cryptoToken, alias, encryptedBytes);
            assertNotNull("Decrypted key pair should not be null", keys);
            // Throws exception is testing does not work
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);

            byte[] encodedPublicKey = keys.getPublic().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey", keys.getPublic().getClass().getName());
            assertEquals("X.509", keys.getPublic().getFormat());
            assertEquals("RSA", keys.getPublic().getAlgorithm());
            assertNotNull("Encoded public key should not be null", encodedPublicKey);
            byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey", keys.getPrivate().getClass().getName());
            assertEquals("PKCS#8", keys.getPrivate().getFormat());
            assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        }
        {
            final KeyPair keypair = KeyTools.genKeys("secp256r1",  AlgorithmConstants.KEYALGORITHM_EC);
            byte[] encryptedBytes = CryptoTools.encryptKeys(cryptoToken, alias, keypair);
            assertNotNull("Encrypted key pair should not be null", encryptedBytes);
            final KeyPair keys = CryptoTools.decryptKeys(cryptoToken, alias, encryptedBytes);
            assertNotNull("Decrypted key pair should not be null", keys);
            // Throws exception is testing does not work
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);

            byte[] encodedPublicKey = keys.getPublic().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey", keys.getPublic().getClass().getName());
            assertEquals("X.509", keys.getPublic().getFormat());
            assertEquals("EC", keys.getPublic().getAlgorithm());
            assertNotNull("Encoded public key should not be null", encodedPublicKey);
            byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey", keys.getPrivate().getClass().getName());
            assertEquals("PKCS#8", keys.getPrivate().getFormat());
            assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        }
        {
            final KeyPair keypair = KeyTools.genKeys("DSA1024",  AlgorithmConstants.KEYALGORITHM_DSA);
            byte[] encryptedBytes = CryptoTools.encryptKeys(cryptoToken, alias, keypair);
            assertNotNull("Encrypted key pair should not be null", encryptedBytes);
            final KeyPair keys = CryptoTools.decryptKeys(cryptoToken, alias, encryptedBytes);
            assertNotNull("Decrypted key pair should not be null", keys);
            // Throws exception is testing does not work
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);

            byte[] encodedPublicKey = keys.getPublic().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey", keys.getPublic().getClass().getName());
            assertEquals("X.509", keys.getPublic().getFormat());
            assertEquals("DSA", keys.getPublic().getAlgorithm());
            assertNotNull("Encoded public key should not be null", encodedPublicKey);
            byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey", keys.getPrivate().getClass().getName());
            assertEquals("PKCS#8", keys.getPrivate().getFormat());
            assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        }
        {
            final KeyPair keypair = KeyTools.genKeys("Ed25519",  AlgorithmConstants.KEYALGORITHM_ED25519);
            byte[] encryptedBytes = CryptoTools.encryptKeys(cryptoToken, alias, keypair);
            assertNotNull("Encrypted key pair should not be null", encryptedBytes);
            final KeyPair keys = CryptoTools.decryptKeys(cryptoToken, alias, encryptedBytes);
            assertNotNull("Decrypted key pair should not be null", keys);
            // Throws exception is testing does not work
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);

            byte[] encodedPublicKey = keys.getPublic().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey", keys.getPublic().getClass().getName());
            assertEquals("X.509", keys.getPublic().getFormat());
            assertEquals("Ed25519", keys.getPublic().getAlgorithm());
            assertNotNull("Encoded public key should not be null", encodedPublicKey);
            byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey", keys.getPrivate().getClass().getName());
            assertEquals("PKCS#8", keys.getPrivate().getFormat());
            assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        }
        {
            final KeyPair keypair = KeyTools.genKeys("Ed448",  AlgorithmConstants.KEYALGORITHM_ED448);
            byte[] encryptedBytes = CryptoTools.encryptKeys(cryptoToken, alias, keypair);
            assertNotNull("Encrypted key pair should not be null", encryptedBytes);
            final KeyPair keys = CryptoTools.decryptKeys(cryptoToken, alias, encryptedBytes);
            assertNotNull("Decrypted key pair should not be null", keys);
            // Throws exception is testing does not work
            KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);

            byte[] encodedPublicKey = keys.getPublic().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey", keys.getPublic().getClass().getName());
            assertEquals("X.509", keys.getPublic().getFormat());
            assertEquals("Ed448", keys.getPublic().getAlgorithm());
            assertNotNull("Encoded public key should not be null", encodedPublicKey);
            byte[] encodedPrivateKey = keys.getPrivate().getEncoded();
            assertEquals("org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey", keys.getPrivate().getClass().getName());
            assertEquals("PKCS#8", keys.getPrivate().getFormat());
            assertNotNull("Encoded private key should not be null", encodedPrivateKey);
        }
    }
    
    /** Test that we can encrypt and decrypt a SecretKeySpec with AES key. */
    @Test
    public void testEncryptDecryptSecret() throws NoSuchSlotException, InvalidAlgorithmParameterException, CryptoTokenOfflineException, IOException, InvalidKeyException {
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), new Properties(), null, 111, "Soft CryptoToken");
        final String alias = "alias";
        cryptoToken.generateKeyPair(KeyGenParams.builder("1024").build(), alias);
        final String base64Key = "7tUe3OLf3xO4BGV0q0NPYlu2du4zJuUPzKeJDg5NRJo";
        final SecretKeySpec key = new SecretKeySpec(Base64.decodeURLSafe(base64Key), "AES");
        final byte[] encryptedBytes = CryptoTools.encryptKey(cryptoToken, alias, key);
        assertNotNull("Encrypted shared key should not be null", encryptedBytes);
        final SecretKeySpec decryptedKey = CryptoTools.decryptKey(cryptoToken, alias, encryptedBytes);
        assertNotNull("Decrypted shared key should not be null", decryptedKey);
        assertNotEquals("Encrypted and decrypted shared key should not be equal", encryptedBytes, decryptedKey.getEncoded());
        assertEquals("RAW", decryptedKey.getFormat());
        assertEquals("AES", decryptedKey.getAlgorithm());
        //assertEquals("org.bouncycastle.jcajce.provider.symmetric.AES", decryptedKey.getClass().getName());
        assertEquals("javax.crypto.spec.SecretKeySpec", decryptedKey.getClass().getName());
    }

}
