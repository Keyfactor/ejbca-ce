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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 *
 * @version $Id$
 *
 */
public abstract class CryptoTokenTestBase {

    public static final String tokenpin = PKCS11TestUtils.getPkcs11SlotPin("userpin1");

    private static final InternalResources intres = InternalResources.getInstance();

    public CryptoTokenTestBase() {
        super();
    }

    /**
     * @param cryptoToken
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws CryptoTokenOfflineException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws InvalidAlgorithmParameterException
     */
    protected void doCryptoTokenRSA(CryptoToken cryptoToken) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException,
            CryptoTokenOfflineException, NoSuchProviderException,
            InvalidKeyException, SignatureException,
            CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmParameterException {
                // We have not activated the token so status should be offline
                assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
                assertEquals(getProvider(), cryptoToken.getSignProviderName());

                // First we start by deleting all old entries
                try {
                    cryptoToken.deleteEntry("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                cryptoToken.activate(tokenpin.toCharArray());
                // Should still be ACTIVE now, because we run activate
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
                cryptoToken.deleteEntry("rsatest00001");
                cryptoToken.deleteEntry("rsatest00002");
                cryptoToken.deleteEntry("rsatest00003");

                // Try to delete something that surely does not exist, it should work without error
                cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

                // Generate the first key
                cryptoToken.generateKeyPair("1024", "rsatest00001");
                PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
                PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));
                String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

                // Make sure keys are or are not extractable, according to what is allowed by the token
                cryptoToken.testKeyPair("rsatest00001");

                // Generate new keys again
                cryptoToken.generateKeyPair("2048", "rsatest00002");
                priv = cryptoToken.getPrivateKey("rsatest00002");
                pub = cryptoToken.getPublicKey("rsatest00002");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(2048, KeyTools.getKeyLength(pub));
                String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
                assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
                priv = cryptoToken.getPrivateKey("rsatest00001");
                pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));
                String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
                assertEquals(keyhash, previouskeyhash);

                // Delete a key pair
                cryptoToken.deleteEntry("rsatest00001");
                try {
                    priv = cryptoToken.getPrivateKey("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                try {
                    pub = cryptoToken.getPublicKey("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                try {
                    // the other keys should still be there
                    priv = cryptoToken.getPrivateKey("rsatest00002");
                    pub = cryptoToken.getPublicKey("rsatest00002");
                    KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                    assertEquals(2048, KeyTools.getKeyLength(pub));
                    String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
                    assertEquals(newkeyhash, newkeyhash2);

                    // Create keys using AlgorithmParameterSpec
                    AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
                    cryptoToken.generateKeyPair(paramspec, "rsatest00003");
                    priv = cryptoToken.getPrivateKey("rsatest00003");
                    pub = cryptoToken.getPublicKey("rsatest00003");
                    KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                    assertEquals(2048, KeyTools.getKeyLength(pub));
                    String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
                    // Make sure it's not the same key
                    assertFalse(newkeyhash2.equals(newkeyhash3));
                } finally {
                    // Clean up and delete our generated keys
                    cryptoToken.deleteEntry("rsatest00002");
                    cryptoToken.deleteEntry("rsatest00003");
                }
            }

    protected void doCryptoTokenDSA(CryptoToken cryptoToken) throws KeyStoreException,
    NoSuchAlgorithmException, CertificateException, IOException,
    CryptoTokenOfflineException, NoSuchProviderException,
    InvalidKeyException, SignatureException,
    CryptoTokenAuthenticationFailedException,
    InvalidAlgorithmParameterException {
        // We have not activated the token so status should be offline
        assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
        assertEquals(getProvider(), cryptoToken.getSignProviderName());

        // First we start by deleting all old entries
        try {
            cryptoToken.deleteEntry("dsatest00001");
            assertTrue("Should throw", false);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD
        }
        cryptoToken.activate(tokenpin.toCharArray());
        // Should still be ACTIVE now, because we run activate
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        cryptoToken.deleteEntry("dsatest00001");
        cryptoToken.deleteEntry("dsatest00002");
        cryptoToken.deleteEntry("dsatest00003");

        // Try to delete something that surely does not exist, it should work without error
        cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

        // Generate the first key
        cryptoToken.generateKeyPair("DSA1024", "dsatest00001");
        PrivateKey priv = cryptoToken.getPrivateKey("dsatest00001");
        PublicKey pub = cryptoToken.getPublicKey("dsatest00001");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

        // Make sure keys are or are not extractable, according to what is allowed by the token
        cryptoToken.testKeyPair("dsatest00001");

        // Generate new keys again
        cryptoToken.generateKeyPair("DSA1024", "dsatest00002");
        priv = cryptoToken.getPrivateKey("dsatest00002");
        pub = cryptoToken.getPublicKey("dsatest00002");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
        assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
        priv = cryptoToken.getPrivateKey("dsatest00001");
        pub = cryptoToken.getPublicKey("dsatest00001");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
        assertEquals(keyhash, previouskeyhash);

        // Delete a key pair
        cryptoToken.deleteEntry("dsatest00001");
        try {
            priv = cryptoToken.getPrivateKey("dsatest00001");
            assertTrue("Should throw", false);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD
        }
        try {
            pub = cryptoToken.getPublicKey("dsatest00001");
            assertTrue("Should throw", false);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD
        }
        // the other keys should still be there
        priv = cryptoToken.getPrivateKey("dsatest00002");
        pub = cryptoToken.getPublicKey("dsatest00002");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
        assertEquals(newkeyhash, newkeyhash2);

        // Create keys using AlgorithmParameterSpec
        AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
        cryptoToken.generateKeyPair(paramspec, "dsatest00003");
        priv = cryptoToken.getPrivateKey("dsatest00003");
        pub = cryptoToken.getPublicKey("dsatest00003");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
        // Make sure it's not the same key
        assertFalse(newkeyhash2.equals(newkeyhash3));

        // Clean up and delete our generated keys
        cryptoToken.deleteEntry("dsatest00002");
        cryptoToken.deleteEntry("dsatest00003");
    }

    /**
     * @param cryptoToken
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws CryptoTokenOfflineException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws InvalidAlgorithmParameterException
     */
    protected void doCryptoTokenECC(CryptoToken cryptoToken, String curve1, int keyLen1, String curve2, int keyLen2) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException,
            CryptoTokenOfflineException, NoSuchProviderException,
            InvalidKeyException, SignatureException,
            CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmParameterException {
                // We have not activated the token so status should be offline
                assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
                assertEquals(getProvider(), cryptoToken.getSignProviderName());

                // First we start by deleting all old entries
                try {
                    cryptoToken.deleteEntry("ecctest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                cryptoToken.activate(tokenpin.toCharArray());
                // Should still be ACTIVE now, because we run activate
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
                cryptoToken.deleteEntry("ecctest00001");
                cryptoToken.deleteEntry("ecctest00002");
                cryptoToken.deleteEntry("ecctest00003");

                // Try to delete something that surely does not exist, it should work without error
                cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

                // Generate the first key
                cryptoToken.generateKeyPair(curve1, "ecctest00001");
                PrivateKey priv = cryptoToken.getPrivateKey("ecctest00001");
                PublicKey pub = cryptoToken.getPublicKey("ecctest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen1, KeyTools.getKeyLength(pub));
                String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

                // Make sure keys are or are not extractable, according to what is allowed by the token
                cryptoToken.testKeyPair("ecctest00001");

                // Generate new keys again
                cryptoToken.generateKeyPair(curve2, "ecctest00002");
                priv = cryptoToken.getPrivateKey("ecctest00002");
                pub = cryptoToken.getPublicKey("ecctest00002");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen2, KeyTools.getKeyLength(pub));
                String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
                assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
                priv = cryptoToken.getPrivateKey("ecctest00001");
                pub = cryptoToken.getPublicKey("ecctest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen1, KeyTools.getKeyLength(pub));
                String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
                assertEquals(keyhash, previouskeyhash);

                // Delete a key pair
                cryptoToken.deleteEntry("ecctest00001");
                try {
                    priv = cryptoToken.getPrivateKey("ecctest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                try {
                    pub = cryptoToken.getPublicKey("ecctest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                // the other keys should still be there
                priv = cryptoToken.getPrivateKey("ecctest00002");
                pub = cryptoToken.getPublicKey("ecctest00002");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen2, KeyTools.getKeyLength(pub));
                String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
                assertEquals(newkeyhash, newkeyhash2);

                // Create keys using AlgorithmParameterSpec
                AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
                cryptoToken.generateKeyPair(paramspec, "ecctest00003");
                priv = cryptoToken.getPrivateKey("ecctest00003");
                pub = cryptoToken.getPublicKey("ecctest00003");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen2, KeyTools.getKeyLength(pub));
                String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
                // Make sure it's not the same key
                assertFalse(newkeyhash2.equals(newkeyhash3));

                // Clean up and delete our generated keys
                cryptoToken.deleteEntry("ecctest00002");
                cryptoToken.deleteEntry("ecctest00003");
            }

    /**
     * @param cryptoToken
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     */
    protected void doActivateDeactivate(CryptoToken cryptoToken)
            throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, NoSuchProviderException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException {
                // We have not activated the token so status should be offline
                assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
                assertEquals(getProvider(), cryptoToken.getSignProviderName());

                // First we start by deleting all old entries
                try {
                    cryptoToken.deleteEntry("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                try {
                    // Generate a key, should not work either
                    cryptoToken.generateKeyPair("1024", "rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
                cryptoToken.activate(tokenpin.toCharArray());
                // Should still be ACTIVE now, because we run activate
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
                cryptoToken.deleteEntry("rsatest00001");

                // Generate a key, should work
                cryptoToken.generateKeyPair("1024", "rsatest00001");
                PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
                PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));

                // Get a key that does not exist
                try {
                    pub = cryptoToken.getPublicKey("sdfsdf77474");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    assertTrue(e.getMessage(), e.getMessage().contains(intres.getLocalizedMessage("token.errornosuchkey", "sdfsdf77474")));
                }
                // We have not set auto activate, so the internal key storage in CryptoToken is emptied
                cryptoToken.deactivate();
                try {
                    priv = cryptoToken.getPrivateKey("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    assertTrue(e.getMessage(), e.getMessage().contains("keyStore (111) == null"));
                }
                try {
                    pub = cryptoToken.getPublicKey("rsatest00001");
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    assertTrue(e.getMessage(), e.getMessage().contains("keyStore (111) == null"));
                }
                // Activate with wrong PIN should not work
                try {
                    cryptoToken.activate("gfhf56564".toCharArray());
                    fail("Should have thrown");
                } catch (CryptoTokenAuthenticationFailedException e) {
                    String strsoft = "PKCS12 key store mac invalid - wrong password or corrupted file.";
                    String strp11 = "Failed to initialize PKCS11 provider slot '1'.";
                    assert(e.getMessage().equals(strsoft)||e.getMessage().equals(strp11));
                }
                cryptoToken.activate(tokenpin.toCharArray());
                priv = cryptoToken.getPrivateKey("rsatest00001");
                pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));

                // End by deleting all old entries
                cryptoToken.deleteEntry("rsatest00001");
            }

    /**
     * @param cryptoToken
     * @throws CryptoTokenOfflineException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws InvalidAlgorithmParameterException
     */
    protected void doAutoActivate(CryptoToken cryptoToken)
            throws CryptoTokenOfflineException, KeyStoreException,
            NoSuchProviderException, NoSuchAlgorithmException,
            CertificateException, IOException, InvalidKeyException,
            SignatureException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmParameterException {
                Properties prop = cryptoToken.getProperties();
                prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);
                cryptoToken.setProperties(prop);

                // We have autoactivation, so status should be ACTIVE
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
                assertEquals(getProvider(), cryptoToken.getSignProviderName());

                cryptoToken.deactivate();
                // It should autoactivate getting status
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
                cryptoToken.activate(tokenpin.toCharArray());
                assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());

                // Generate a key
                cryptoToken.generateKeyPair("1024", "rsatest00001");
                PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
                PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));
                // Deactivate
                cryptoToken.deactivate();
                // It should autoactivate trying to get keys
                priv = cryptoToken.getPrivateKey("rsatest00001");
                pub = cryptoToken.getPublicKey("rsatest00001");
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));

                // End by deleting all old entries
                cryptoToken.deleteEntry("rsatest00001");
            }

    protected void doStoreAndLoad(CryptoToken cryptoToken) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchProviderException,
            InvalidAlgorithmParameterException, SignatureException, NoSuchSlotException {
        cryptoToken.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        cryptoToken.deleteEntry("rsatest00001");

        // Generate a key
        cryptoToken.generateKeyPair("1024", "rsatest00001");
        PrivateKey priv = cryptoToken.getPrivateKey("rsatest00001");
        PublicKey pub = cryptoToken.getPublicKey("rsatest00001");
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String pubKHash = CertTools.getFingerprintAsString(pub.getEncoded());
        assertEquals(111, cryptoToken.getId()); // What we set in "createCryptoToken"

        // Serialize the token and re-create it from scratch
        Properties prop = cryptoToken.getProperties();
        byte[] data = cryptoToken.getTokenData();
        // prop and data can now be persisted somewhere and retrieved again a week later
        CryptoToken token2 = CryptoTokenFactory.createCryptoToken(cryptoToken.getClass().getName(), prop, data, 555, "Another cryptoToken");
        token2.activate(tokenpin.toCharArray());
        // Now we have a new crypto token, so lets do the same key test again
        priv = token2.getPrivateKey("rsatest00001");
        pub = token2.getPublicKey("rsatest00001");
        KeyTools.testKey(priv, pub, token2.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String pubKHash2 = CertTools.getFingerprintAsString(pub.getEncoded());
        assertEquals(pubKHash, pubKHash2);
        assertEquals(555, token2.getId()); // What we set in "createCryptoToken"

        // Clean up by deleting key
        cryptoToken.deleteEntry("rsatest00001");
    }

    protected void doGenerateSymKey(CryptoToken cryptoToken) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException,
            SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException,
            NoSuchSlotException {
        cryptoToken.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        cryptoToken.deleteEntry("aestest00001");
        // Generate the symm key
        cryptoToken.generateKey("AES", 256, "aestest00001");
        Key symkey = cryptoToken.getKey("aestest00001");
        // Encrypt something with the key, must be multiple of 16 bytes for AES (need to do padding on your own)
        String input = "1234567812345678";
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", cryptoToken.getEncProviderName());
        IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, symkey, ivSpec);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, symkey, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        assertEquals(input, new String(plainText));

        // Serialize the token and re-create it from scratch
        Properties prop = cryptoToken.getProperties();
        byte[] data = cryptoToken.getTokenData();
        CryptoToken token2 = CryptoTokenFactory.createCryptoToken(cryptoToken.getClass().getName(), prop, data, 555, "Some cryptoToken");
        token2.activate(tokenpin.toCharArray());
        // Now we have a new crypto token, so lets do the same hmac again and compare
        Key symkey2 = token2.getKey("aestest00001");
        cipher.init(Cipher.DECRYPT_MODE, symkey2, ivSpec);
        plainText = cipher.doFinal(cipherText);
        assertEquals(input, new String(plainText));
        // Make sure the decryption fails as well, again multiple of 16 bytes
        String input2 = "2345678923456789";
        cipher.init(Cipher.DECRYPT_MODE, symkey2, ivSpec);
        plainText = cipher.doFinal(input2.getBytes());
        assertFalse(input.equals(new String(Hex.encode(plainText))));

        // Test that we can use the key for wrapping as well
//      KeyPair kp = KeyTools.genKeys("512", "RSA");
//      Cipher c = Cipher.getInstance("AES/CBC/NoPadding", token.getEncProviderName());
//        c.init( Cipher.WRAP_MODE, symkey2 );
//        byte[] wrappedkey = c.wrap( kp.getPrivate() );
//        Cipher c2 = Cipher.getInstance( "AES/CBC/NoPadding" );
//        c2.init(Cipher.UNWRAP_MODE, symkey2);
//        Key unwrappedkey = c.unwrap(wrappedkey, "RSA", Cipher.PRIVATE_KEY);
//        KeyTools.testKey((PrivateKey)unwrappedkey, kp.getPublic(), "BC");

        // Clean up by deleting key
        cryptoToken.deleteEntry("aestest00001");
    }

    /* Not used because HMAC on HSMs is too hard... keep for future reference though 
    protected void doGenerateHmacKey(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException {
        token.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());

        try {
            token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
            // Generate the symm key
            token.generateKey("AES", 256, "aestest00001");
            //token.generateKey("DES", 64, "aestest00001");
            Key hMacKey = token.getKey("aestest00001");
            // HMac something with the key
            String input = "12345678";
            Mac hMac = Mac.getInstance("HmacSHA256", token.getSignProviderName());
            hMac.init(hMacKey);
            hMac.update(input.getBytes());
            byte[] bytes = hMac.doFinal();

            // Serialize the token and re-create it from scratch
            Properties prop = token.getProperties();
            byte[] data = token.getTokenData();
            CryptoToken token2 = CryptoTokenFactory.createCryptoToken(token.getClass().getName(), prop, data, 555);
            token2.activate(tokenpin.toCharArray());
            // Now we have a new crypto token, so lets do the same hmac again and compare
            hMacKey = token2.getKey("aestest00001");
            hMac.init(hMacKey);
            hMac.update(input.getBytes());
            byte[] bytes1 = hMac.doFinal();
            assertEquals(new String(Hex.encode(bytes)), new String(Hex.encode(bytes1)));
            // Make sure the HMAC fails as well
            String input2 = "23456789";
            hMac.init(hMacKey);
            hMac.update(input2.getBytes());
            byte[] bytes2 = hMac.doFinal();
            assertFalse(new String(Hex.encode(bytes)).equals(new String(Hex.encode(bytes2))));
        } finally {
            // Clean up by deleting key
            //token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
        }
    }
    */
    
    protected void doExtractKeyFalse(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException {

        assertFalse("Token should not allow extraction on this test", token.doPermitExtractablePrivateKey());

        //create encryption key
        token.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
        token.deleteEntry("encryptkeytest001");
        token.generateKey("DESede", 128, "encryptkeytest001");

        //create the key pair
        token.generateKeyPair("1024", "extractkeytest001");
        token.testKeyPair("extractkeytest001");

        //extract the private key
        try {
            token.extractKey("DESede/ECB/PKCS5Padding", "encryptkeytest001", "extractkeytest001");
            fail("Should have received an exception");
        } catch (PrivateKeyNotExtractableException e) {
            // NOPMD
        } catch (InvalidKeyException e) {
            // NOPMD
        }
        token.deleteEntry("encryptkeytest001");
        token.deleteEntry("extractkeytest001");

    }

    protected void doExtractKey(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, PrivateKeyNotExtractableException, BadPaddingException, InvalidKeySpecException {

        assertTrue("Token should allow extraction on this test", token.doPermitExtractablePrivateKey());

        //create encryption key
        token.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
        try {
            token.deleteEntry("encryptkeytest001");
            token.deleteEntry("extractkeytest001");
            token.generateKey("DESede", 168, "encryptkeytest001");

            //create the key pair
            try {
                token.generateKeyPair("1024", "extractkeytest001");
            } catch (java.security.ProviderException e ) {
                fail("Unable to generate extractable private key, this failure is normal on a SafeNet Luna, but should work on a Utimaco and SafeNet ProtectServer.");
            }
            token.testKeyPair("extractkeytest001");

            //extract the private key
            byte[] cbcIv = { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD, (byte)0xEF };
            IvParameterSpec ivParam = new IvParameterSpec( cbcIv );
            byte[] wrappedkey = token.extractKey("DESede/CBC/PKCS5Padding", ivParam, "encryptkeytest001", "extractkeytest001");

            //get encryption key
            Key encryptionKey = token.getKey("encryptkeytest001");
            
            //unwrap private key and check if it is ok
            // since SUN PKCS11 Provider does not implements WRAP_MODE,
            // DECRYPT_MODE with encoded private key will be used instead, giving the same result
            Cipher c = Cipher.getInstance( "DESede/CBC/PKCS5Padding", token.getEncProviderName());
            c.init(Cipher.DECRYPT_MODE, encryptionKey, ivParam);
            byte[] decryptedBytes = c.doFinal(wrappedkey);

            KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decryptedBytes);
            PrivateKey unwrappedkey = kf.generatePrivate(ks);

            KeyTools.testKey((PrivateKey)unwrappedkey, token.getPublicKey("extractkeytest001"), BouncyCastleProvider.PROVIDER_NAME);

            assertEquals(token.getPrivateKey("extractkeytest001"), unwrappedkey);
        } catch (PrivateKeyNotExtractableException e) {
            fail("Private key is not extractable, this failure is normal on a SafeNet Luna, but should work on a Utimaco and SafeNet ProtectServer.");
        } finally {
            token.deleteEntry("encryptkeytest001");
            token.deleteEntry("extractkeytest001");
        }
    }

    abstract String getProvider();
}
