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
package org.cesecore.keys.token.p11ng;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

/**
 */
public abstract class CryptoTokenTestBase {
    
    private static Logger log = Logger.getLogger(CryptoTokenTestBase.class);

    private static final String PROPERTYFILE = "/systemtests.properties";
    private static Properties properties = null;
    
    private static final String PKCS11_LIBRARY = "pkcs11.library";
    private static final String PKCS11_SECURITY_PROVIDER = "pkcs11.provider";
    private static final String PKCS11_SLOT_PIN = "pkcs11.slotpin";
    private static final String PKCS11_SLOT_VALUE = "pkcs11.slottypevalue"; 
    private static final String PKCS11_SLOT_TYPE = "pkcs11.slottype"; 

    
    private static final String UTIMACO_PKCS11_LINUX_LIB = "/etc/utimaco/libcs2_pkcs11.so";
    private static final String UTIMACO_PKCS11_WINDOWS_LIB = "C:/Program Files/Utimaco/SafeGuard CryptoServer/Lib/cs2_pkcs11.dll";
    private static final String LUNASA_PKCS11_LINUX_LIB = "/usr/lunasa/lib/libCryptoki2_64.so";
    private static final String LUNASA_PKCS11_LINUX32_LIB = "/usr/lunasa/lib/libCryptoki2.so";
    private static final String PROTECTSERVER_PKCS11_LINUX_LIB = "/opt/PTK/lib/libcryptoki.so"; // this symlink is set by safeNet-install.sh->"5 Set the default cryptoki and/or hsm link". Use it instead of symlinking manually.
    private static final String PROTECTSERVER_PKCS11_LINUX64_LIB = "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_LINUX32_LIB = "/opt/ETcpsdk/lib/linux-i386/libcryptoki.so";
    private static final String PROTECTSERVER_PKCS11_WINDOWS_LIB = "C:/Program Files/SafeNet/ProtectToolkit C SDK/bin/sw/cryptoki.dll";
    

    public static final String tokenpin = getPkcs11SlotPin();

    private static final String JACKNJI_NAME = "org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken";
    
    private static final String strsoft = "PKCS12 key store mac invalid - wrong password or corrupted file.";
    private static String strp11 = "Failed to initialize PKCS11 provider slot "; // should be appended with real value, i.e. '1'
    private static final String slotIndexP11Ng = PKCS11TestUtils.getPkcs11SlotValue("0"); // Test should run on slot with index 0
    private static final String slotIdP11Ng = "0"; // Test should run on slot with id 0
    private static final String strP11Ng = "Failed to login to PKCS#11 provider slot '" + slotIndexP11Ng + "': 0x000000a" + slotIdP11Ng
            + ": PIN_INCORRECT";

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
    protected void doCryptoTokenRSA(CryptoToken cryptoToken) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            CryptoTokenOfflineException, NoSuchProviderException, InvalidKeyException, SignatureException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmParameterException {
        // We have not activated the token so status should be offline
        assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());

        cryptoToken.activate(tokenpin.toCharArray());
        // Should still be ACTIVE now, because we run activate
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        assertEquals(getProvider(), cryptoToken.getSignProviderName());
        cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_2);
        cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_3);

        // Try to delete something that surely does not exist, it should work without error
        cryptoToken.deleteEntry(PKCS11TestUtils.NON_EXISTING_KEY);

        // Generate the first key
        cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_1024, PKCS11TestUtils.RSA_TEST_KEY_1);
        PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
        PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

        // Make sure keys are or are not extractable, according to what is allowed by the token
        cryptoToken.testKeyPair(PKCS11TestUtils.RSA_TEST_KEY_1);
        // Generate new keys again
        cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_2048, PKCS11TestUtils.RSA_TEST_KEY_2);
        priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_2);
        pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_2);
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(2048, KeyTools.getKeyLength(pub));
        String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
        assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
        priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
        pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
        KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
        assertEquals(1024, KeyTools.getKeyLength(pub));
        String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
        assertEquals(keyhash, previouskeyhash);

        // Delete a key pair
        cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        try {
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            assertTrue("Should throw", false);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD
        }
        try {
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            assertTrue("Should throw", false);
        } catch (CryptoTokenOfflineException e) {
            // NOPMD
        }
        try {
            // the other keys should still be there
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_2);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_2);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(2048, KeyTools.getKeyLength(pub));
            String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(newkeyhash, newkeyhash2);

            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                // Create keys using AlgorithmParameterSpec
                AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
                cryptoToken.generateKeyPair(paramspec, PKCS11TestUtils.RSA_TEST_KEY_3);
                priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_3);
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_3);
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(2048, KeyTools.getKeyLength(pub));
                String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
                // Make sure it's not the same key
                assertFalse(newkeyhash2.equals(newkeyhash3));
            }
        } finally {
            // Clean up and delete our generated keys
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_2);
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_3);
        }
    }

    protected void doCryptoTokenDSA(CryptoToken cryptoToken) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            CryptoTokenOfflineException, InvalidKeyException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmParameterException {
        try {
            // We have not activated the token so status should be offline
            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
            assertEquals(getProvider(), cryptoToken.getSignProviderName());

            cryptoToken.activate(tokenpin.toCharArray());
            // Should still be ACTIVE now, because we run activate
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_1);
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_2);
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_3);

            // Try to delete something that surely does not exist, it should work without error
            cryptoToken.deleteEntry(PKCS11TestUtils.NON_EXISTING_KEY);

            // Generate the first key
            cryptoToken.generateKeyPair("DSA1024", PKCS11TestUtils.DSA_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

            // Make sure keys are or are not extractable, according to what is allowed by the token
            cryptoToken.testKeyPair(PKCS11TestUtils.DSA_TEST_KEY_1);

            // Generate new keys again
            cryptoToken.generateKeyPair("DSA1024", PKCS11TestUtils.DSA_TEST_KEY_2);
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_2);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_2);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
            assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_1);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(keyhash, previouskeyhash);

            // Delete a key pair
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_1);
            try {
                priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_1);
                assertTrue("Should throw", false);
            } catch (CryptoTokenOfflineException e) {
                // NOPMD
            }
            try {
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_1);
                assertTrue("Should throw", false);
            } catch (CryptoTokenOfflineException e) {
                // NOPMD
            }
            // the other keys should still be there
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_2);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_2);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(newkeyhash, newkeyhash2);

            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                // Create keys using AlgorithmParameterSpec
                AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
                cryptoToken.generateKeyPair(paramspec, PKCS11TestUtils.DSA_TEST_KEY_3);
                priv = cryptoToken.getPrivateKey(PKCS11TestUtils.DSA_TEST_KEY_3);
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.DSA_TEST_KEY_3);
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(1024, KeyTools.getKeyLength(pub));
                String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
                // Make sure it's not the same key
                assertFalse(newkeyhash2.equals(newkeyhash3));
            }
        } finally {

            // Clean up and delete our generated keys
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_1);
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_2);
            cryptoToken.deleteEntry(PKCS11TestUtils.DSA_TEST_KEY_3);
        }
    }

    /** Tests generation and deletion of ECC or EdDSA keys on a soft crypto token or HSM.
     * SInce EdDSA is a "variation" or ECDSA this method works for both.
     * 
     * @param cryptoToken the crypto token to generate keys in
     * @param curve1 curve of the first key to generate, e.g. secp256r, Ed25519, etc
     * @param keyLen1 the key length the key has, for comparison that the right key length was generated, e.g. 256, 255, etc
     * @param curve2 curve of a second key to generate, will be compared with the first so it's not the same
     * @param keyLen2 the key length the key has, for comparison that the right key length was generated
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
            NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException, NoSuchProviderException, InvalidKeyException,
            SignatureException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmParameterException {

        try {
            // We have not activated the token so status should be offline
            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());

            cryptoToken.activate(tokenpin.toCharArray());
            // Should still be ACTIVE now, because we run activate
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            assertEquals(getProvider(), cryptoToken.getSignProviderName());
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_1);
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_2);
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_3);

            // Try to delete something that surely does not exist, it should work without error
            cryptoToken.deleteEntry(PKCS11TestUtils.NON_EXISTING_KEY);

            // Generate the first key
            cryptoToken.generateKeyPair(curve1, PKCS11TestUtils.ECC_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(keyLen1, KeyTools.getKeyLength(pub));
            String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

            // Make sure keys are or are not extractable, according to what is allowed by the token
            cryptoToken.testKeyPair(PKCS11TestUtils.ECC_TEST_KEY_1);

            // Generate new keys again
            cryptoToken.generateKeyPair(curve2, PKCS11TestUtils.ECC_TEST_KEY_2);
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_2);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_2);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(keyLen2, KeyTools.getKeyLength(pub));
            String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
            assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_1);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(keyLen1, KeyTools.getKeyLength(pub));
            String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(keyhash, previouskeyhash);

            // Delete a key pair
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_1);
            try {
                priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_1);
                assertTrue("Should throw", false);
            } catch (CryptoTokenOfflineException e) {
                // NOPMD
            }
            try {
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_1);
                assertTrue("Should throw", false);
            } catch (CryptoTokenOfflineException e) {
                // NOPMD
            }
            // the other keys should still be there
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_2);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_2);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(keyLen2, KeyTools.getKeyLength(pub));
            String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(newkeyhash, newkeyhash2);

            // Create keys using AlgorithmParameterSpec
            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
                cryptoToken.generateKeyPair(paramspec, PKCS11TestUtils.ECC_TEST_KEY_3);
                priv = cryptoToken.getPrivateKey(PKCS11TestUtils.ECC_TEST_KEY_3);
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.ECC_TEST_KEY_3);
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
                assertEquals(keyLen2, KeyTools.getKeyLength(pub));
                String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
                // Make sure it's not the same key
                assertFalse(newkeyhash2.equals(newkeyhash3));
            }

        } finally {
            // Clean up and delete our generated keys
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_1);
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_2);
            cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_3);
        }
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
    protected void doActivateDeactivate(CryptoToken cryptoToken) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        try {

            // We have not activated the token so status should be offline
            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());

            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                try {
                    // Generate a key, should not work either
                    cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_1024, PKCS11TestUtils.RSA_TEST_KEY_1);
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    // NOPMD
                }
            }
            cryptoToken.activate(tokenpin.toCharArray());
            // Should still be ACTIVE now, because we run activate
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            assertEquals(getProvider(), cryptoToken.getSignProviderName());
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);

            // Generate a key, should work
            cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_1024, PKCS11TestUtils.RSA_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            // Get a key that does not exist
            try {
                pub = cryptoToken.getPublicKey(PKCS11TestUtils.NON_EXISTING_KEY);
                assertTrue("Should throw", false);
            } catch (CryptoTokenOfflineException e) {
                assertTrue(e.getMessage(), e.getMessage().contains("No key with alias '" + PKCS11TestUtils.NON_EXISTING_KEY + "'."));
            }
            // We have not set auto activate, so the internal key storage in CryptoToken is emptied
            cryptoToken.deactivate();
            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                try {
                    priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    assertTrue(e.getMessage(), e.getMessage().contains("The keys in the crypto token with id 111 could not be accessed. Is the crypto token active? "));
                }
                try {
                    pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
                    assertTrue("Should throw", false);
                } catch (CryptoTokenOfflineException e) {
                    assertTrue(e.getMessage(), e.getMessage().contains("The keys in the crypto token with id 111 could not be accessed. Is the crypto token active? "));
                }
            }
            // Activate with wrong PIN should not work
            try {
                cryptoToken.activate(PKCS11TestUtils.WRONG_PIN.toCharArray());
                fail("Should have thrown");
            } catch (CryptoTokenAuthenticationFailedException e) {
                strp11 = strp11 + "'" + PKCS11TestUtils.getPkcs11SlotValue() + "'.";
                assertTrue("exception is not one of the expected: " + e.getMessage(), e.getMessage().equals(strsoft) || e.getMessage().equals(strp11) || e.getMessage().equals(strP11Ng));
            }
            cryptoToken.activate(tokenpin.toCharArray());
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            if (!cryptoToken.getClass().getCanonicalName().equals(JACKNJI_NAME)) {
                KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            }
            assertEquals(1024, KeyTools.getKeyLength(pub));
        } finally {
            // End by deleting all old entries
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        }
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
     * @throws InterruptedException 
     */
    protected void doAutoActivate(CryptoToken cryptoToken) throws CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException,
            CryptoTokenAuthenticationFailedException, InvalidAlgorithmParameterException, InterruptedException {
        try {
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
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
            cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_2048, PKCS11TestUtils.RSA_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(2048, KeyTools.getKeyLength(pub));
            // Deactivate
            cryptoToken.deactivate();
            // It should autoactivate trying to get keys
            priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(2048, KeyTools.getKeyLength(pub));

        } finally {
            // End by deleting all old entries
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        }
    }

    protected void doStoreAndLoad(CryptoToken cryptoToken) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchSlotException {

        try {
            cryptoToken.activate(tokenpin.toCharArray());
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);

            // Generate a key
            cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_1024, PKCS11TestUtils.RSA_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String pubKHash = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(111, cryptoToken.getId()); // What we set in "createCryptoToken"

            // Serialize the token and re-create it from scratch
            Properties prop = cryptoToken.getProperties();
            byte[] data = cryptoToken.getTokenData();
            // prop and data can now be persisted somewhere and retrieved again a week later
            CryptoToken token2 = createCryptoToken(cryptoToken.getClass().getName(), prop, data, 555, "Another cryptoToken");
            token2.activate(tokenpin.toCharArray());
            // Now we have a new crypto token, so lets do the same key test again
            priv = token2.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            pub = token2.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            KeyTools.testKey(priv, pub, token2.getSignProviderName());
            assertEquals(1024, KeyTools.getKeyLength(pub));
            String pubKHash2 = CertTools.getFingerprintAsString(pub.getEncoded());
            assertEquals(pubKHash, pubKHash2);
            assertEquals(555, token2.getId()); // What we set in "createCryptoToken"
        } finally {
            // Clean up by deleting key
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        }
    }

    protected void doGenerateSymKey(CryptoToken cryptoToken)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException, SignatureException, CertificateException,
            NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, NoSuchSlotException {
        try {
            cryptoToken.activate(tokenpin.toCharArray());
            assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            cryptoToken.deleteEntry("aestest00001");
            // Generate the symm key
            cryptoToken.generateKey("AES", 256, "aestest00001");
            Key symkey = cryptoToken.getKey("aestest00001");
            // Encrypt something with the key, must be multiple of 16 bytes for AES (need to do padding on your own)
            String input = "1234567812345678";
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", cryptoToken.getEncProviderName());
            // Make a real random IV to not give a bad example with fixed IV
            // This _should_ be a SecureRandom, but that can take more time to make it quick with standard Random
            byte[] ivbytes = new byte[16]; // must be 16 bytes
            Random r = new Random();
            r.nextBytes(ivbytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivbytes);
            cipher.init(Cipher.ENCRYPT_MODE, symkey, ivSpec);
            byte[] cipherText = cipher.doFinal(input.getBytes());
            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, symkey, ivSpec);
            byte[] plainText = cipher.doFinal(cipherText);
            assertEquals(input, new String(plainText));

            // Serialize the token and re-create it from scratch
            Properties prop = cryptoToken.getProperties();
            byte[] data = cryptoToken.getTokenData();
            CryptoToken token2 = createCryptoToken(cryptoToken.getClass().getName(), prop, data, 555, "Some cryptoToken");
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
        } finally {
            // Clean up by deleting key
            cryptoToken.deleteEntry("aestest00001");
        }
    }


    protected abstract String getProvider();
    
    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static final CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName) throws NoSuchSlotException {
        final boolean allowNonExistingSlot = Boolean.valueOf(properties.getProperty(CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY, Boolean.FALSE.toString()));
        return createCryptoToken(inClassname, properties, data, cryptoTokenId, tokenName, allowNonExistingSlot);
    }

    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken, potentially enabling public key authentication to the token.
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @param allowNonExistingSlot if the NoSuchSlotException should be used
     * @param keyAndCertFinder If specified, an object that can take a name from properties and find a key/cert pair.  Currently, only relevant for Azure Key Vault.
     * throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName, boolean allowNonExistingSlot) throws NoSuchSlotException {
        final String classname = inClassname;

        final CryptoToken token = createTokenFromClass(classname);
        if (token == null) {
            log.error("No token. Classpath=" + classname);
            return null;
        }
        
        try {
            token.init(properties, data, cryptoTokenId);
        } catch (NoSuchSlotException e) {
            final String msg = "Unable to access PKCS#11 slot for crypto token '"+tokenName+"' (" + cryptoTokenId + "). Perhaps the token was removed? " + e.getMessage();
            if (allowNonExistingSlot) {
                log.warn(msg);
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
                throw e;
            }
        } catch (Exception e) {
            log.error("Error initializing Crypto Token '"+tokenName+"' (" + cryptoTokenId + "). Classpath=" + classname, e);
        }
        token.setTokenName(tokenName);
        return token;
    }
    
    private static final CryptoToken createTokenFromClass(final String classpath) {
        try {
            Class<?> implClass = Class.forName(classpath);
            Object obj = implClass.newInstance();
            return (CryptoToken) obj;
        } catch (Throwable e) {
            log.error("Error contructing Crypto Token (setting to null). Classpath="+classpath, e);
            return null;
        }
    }
    
    public  static String getHSMLibrary() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX64_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = utimacoCSLinux.getAbsolutePath();
        } else if (utimacoCSWindows.exists()) {
            ret = utimacoCSWindows.getAbsolutePath();
        } else if (lunaSALinux64.exists()) {
            ret = lunaSALinux64.getAbsolutePath();
        } else if (lunaSALinux32.exists()) {
            ret = lunaSALinux32.getAbsolutePath();
        } else if (protectServerLinux64.exists()) {
            ret = protectServerLinux64.getAbsolutePath();
        } else if (protectServerLinux32.exists()) {
            ret = protectServerLinux32.getAbsolutePath();
        } else if (protectServerLinux.exists()) {
            ret = protectServerLinux.getAbsolutePath();
        } else if (protectServerWindows.exists()) {
            ret = protectServerWindows.getAbsolutePath();
        }
        // Override auto-detected properties if configuration exists
        ret = StringUtils.trim(getSystemTestsProperties().getProperty(PKCS11_LIBRARY, ret));
        if (log.isDebugEnabled()) {
            log.debug("getHSMLibrary: "+ret);
        }
        return ret;
    }
    
    public static String getHSMProvider() {
        final File utimacoCSLinux = new File(UTIMACO_PKCS11_LINUX_LIB);
        final File utimacoCSWindows = new File(UTIMACO_PKCS11_WINDOWS_LIB);
        final File lunaSALinux64 = new File(LUNASA_PKCS11_LINUX_LIB);
        final File lunaSALinux32 = new File(LUNASA_PKCS11_LINUX32_LIB);
        final File protectServerLinux = new File(PROTECTSERVER_PKCS11_LINUX_LIB);
        final File protectServerLinux64 = new File(PROTECTSERVER_PKCS11_LINUX64_LIB);
        final File protectServerLinux32 = new File(PROTECTSERVER_PKCS11_LINUX32_LIB);
        final File protectServerWindows = new File(PROTECTSERVER_PKCS11_WINDOWS_LIB);
        String ret = null;
        if (utimacoCSLinux.exists()) {
            ret = "SunPKCS11-libcs2_pkcs11.so-slot1";
        } else if (utimacoCSWindows.exists()) {
            ret = "SunPKCS11-cs2_pkcs11.dll-slot1";
        } else if (lunaSALinux64.exists()) {
            ret = "SunPKCS11-libCryptoki2_64.so-slot1";
        } else if (lunaSALinux32.exists()) {
            ret = "SunPKCS11-libCryptoki2.so-slot1";
        } else if ( protectServerLinux32.exists() || protectServerLinux64.exists() ||  protectServerLinux.exists()) {
            ret = "SunPKCS11-libcryptoki.so-slot1";
        } else if (protectServerWindows.exists()) {
            ret = "SunPKCS11-cryptoki.dll-slot1";
        }
        // Override auto-detected properties if configuration exists
        ret = StringUtils.trim(getSystemTestsProperties().getProperty(PKCS11_SECURITY_PROVIDER, ret));
        if (log.isDebugEnabled()) {
            log.debug("getHSMProvider: "+ret);
        }
        return ret;
    }
    
    
    /** Returns the configured PKCS#11 slot/token PIN as a string. The default is "userpin1", if not configured. */
    public static String getPkcs11SlotPin() {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_PIN, "userpin1").trim();
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_PIN: "+ret);
        }
        return ret;
    }
    
    /**
     * Returns the configured PKCS#11 slot/token type as a string. The default is "1", if not configured.
     */
    public static String getPkcs11SlotValue() {
        return getPkcs11SlotValue("1");
    }
    
    /**
     * Returns the configured PKCS#11 slot/token type as a string, or the given default value if not configured.
     * <p>
     * <strong>Note:</strong> If the user has configured a different value in systemtests.properties, then that will be returned. Using this method can result in fragile tests.
     */
    public static String getPkcs11SlotValue(String defaultValue) {
        final String ret = getSystemTestsProperties().getProperty(PKCS11_SLOT_VALUE, defaultValue).trim();
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_VALUE: "+ret);
        }
        return ret;
    }
    
    /** @return properties defined in systemtests.properties for override of non-default environments. See also org.cesecore.SystemTestsConfiguration. */
    private static Properties getSystemTestsProperties() {
        if (properties==null) {
            properties = new Properties();
            try {
                final InputStream is = JackNJI11ProviderTest.class.getResourceAsStream(PROPERTYFILE);
                if (is!=null) {
                    properties.load(is);
                    is.close();
                }
            } catch (IOException e) {
                log.warn(e.getMessage());
            }
            if (properties.isEmpty()) {
                log.info(PROPERTYFILE + " was not detected. Defaults will be used.");
            } else {
                log.info(PROPERTYFILE + " was detected.");
            }
        }
        return properties;
    }

    
    /**
     * Returns the configured PKCS#11 slot/token type. The default is Pkcs11SlotLabelType.SLOT_NUMBER
     * 
     * @return A Pkcs11SlotLabelType enum value
     */
    public static Pkcs11SlotLabelType getPkcs11SlotType() {
        final String defaultValue = Pkcs11SlotLabelType.SLOT_NUMBER.getKey();
        final String propertyValue = getSystemTestsProperties().getProperty(PKCS11_SLOT_TYPE, defaultValue);
        final Pkcs11SlotLabelType ret = Pkcs11SlotLabelType.getFromKey(propertyValue.trim());
        if (log.isDebugEnabled()) {
            log.debug("PKCS11_SLOT_TYPE: "+ret.getKey());
        }
        return ret;
    }
}
