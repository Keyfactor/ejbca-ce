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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * This class contains unit tests for the CryptoTools class.
 * 
 * @version $Id$
 *
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
    public void testEncryptDecrypt() throws NoSuchSlotException, InvalidAlgorithmParameterException, CryptoTokenOfflineException, IOException, InvalidKeyException {
        CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), new Properties(), null, 111, "Soft CryptoToken");
        final String alias = "alias";
        cryptoToken.generateKeyPair(KeyGenParams.builder("1024").build(), alias);
        final KeyPair keypair = KeyTools.genKeys("1024",  "RSA");
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

}
