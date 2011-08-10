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
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * 
 * Based on cesecore version:
 *      CryptoTokenTestBase.java 511 2011-03-10 15:23:28Z tomas
 * 
 * @version $Id$
 *
 */
public abstract class CryptoTokenTestBase {

    public static final String tokenpin = "userpin1";


	public CryptoTokenTestBase() {
		super();
	}

	/**
	 * @param catoken
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
	protected void doCryptoTokenRSA(CryptoToken catoken) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			CryptoTokenOfflineException, NoSuchProviderException,
			InvalidKeyException, SignatureException,
			CryptoTokenAuthenticationFailedException,
			InvalidAlgorithmParameterException {
				// We have not activated the token so status should be offline
			    assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			    assertEquals(getProvider(), catoken.getSignProviderName());
			
			    // First we start by deleting all old entries
			    try {
			    	catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    catoken.activate(tokenpin.toCharArray());
			    // Should still be ACTIVE now, because we run activate
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00003");
			
			    // Try to delete something that surely does not exist, it should work without error
			    catoken.deleteEntry(tokenpin.toCharArray(), "sdkfjhsdkfjhsd777");
			
			    // Generate the first key
			    catoken.generateKeyPair("1024", "rsatest00001");
			    PrivateKey priv = catoken.getPrivateKey("rsatest00001");
			    PublicKey pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			
			    // Make sure keys are or are not extractable, according to what is allowed by the token
			    catoken.testKeyPair(priv, pub);
//			    System.out.println(priv);
//			    System.out.println(pub);
			    
			    // Generate new keys again
			    catoken.generateKeyPair("2048", "rsatest00002");
			    priv = catoken.getPrivateKey("rsatest00002");
			    pub = catoken.getPublicKey("rsatest00002");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(2048, KeyTools.getKeyLength(pub));
			    String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
			    priv = catoken.getPrivateKey("rsatest00001");
			    pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			    String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertEquals(keyhash, previouskeyhash);
			
			    // Delete a key pair
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			    try {
			    	priv = catoken.getPrivateKey("rsatest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    try {
			        pub = catoken.getPublicKey("rsatest00001");        
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    // the other keys should still be there
			    priv = catoken.getPrivateKey("rsatest00002");
			    pub = catoken.getPublicKey("rsatest00002");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(2048, KeyTools.getKeyLength(pub));
			    String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertEquals(newkeyhash, newkeyhash2);
			    
			    // Create keys using AlgorithmParameterSpec
			    AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
			    catoken.generateKeyPair(paramspec, "rsatest00003");
			    priv = catoken.getPrivateKey("rsatest00003");
			    pub = catoken.getPublicKey("rsatest00003");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(2048, KeyTools.getKeyLength(pub));
			    String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			    // Make sure it's not the same key
			    assertFalse(newkeyhash2.equals(newkeyhash3));

			    // Clean up and delete our generated keys
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00003");
			}

	/**
	 * @param catoken
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
	protected void doCryptoTokenECC(CryptoToken catoken) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			CryptoTokenOfflineException, NoSuchProviderException,
			InvalidKeyException, SignatureException,
			CryptoTokenAuthenticationFailedException,
			InvalidAlgorithmParameterException {
				// We have not activated the token so status should be offline
			    assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			    assertEquals(getProvider(), catoken.getSignProviderName());
			
			    // First we start by deleting all old entries
			    try {
			    	catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    catoken.activate(tokenpin.toCharArray());
			    // Should still be ACTIVE now, because we run activate
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00001");
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00002");
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00003");

			    // Try to delete something that surely does not exist, it should work without error
			    catoken.deleteEntry(tokenpin.toCharArray(), "sdkfjhsdkfjhsd777");
			
			    // Generate the first key
			    catoken.generateKeyPair("secp256r1", "ecctest00001");
			    PrivateKey priv = catoken.getPrivateKey("ecctest00001");
			    PublicKey pub = catoken.getPublicKey("ecctest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(256, KeyTools.getKeyLength(pub));
			    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			
			    // Make sure keys are or are not extractable, according to what is allowed by the token
			    catoken.testKeyPair(priv, pub);
			    
			    // Generate new keys again
			    catoken.generateKeyPair("secp384r1", "ecctest00002");
			    priv = catoken.getPrivateKey("ecctest00002");
			    pub = catoken.getPublicKey("ecctest00002");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(384, KeyTools.getKeyLength(pub));
			    String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertFalse("New keys are same as old keys, should not be...", keyhash.equals(newkeyhash));
			    priv = catoken.getPrivateKey("ecctest00001");
			    pub = catoken.getPublicKey("ecctest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(256, KeyTools.getKeyLength(pub));
			    String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertEquals(keyhash, previouskeyhash);
			
			    // Delete a key pair
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00001");
			    try {
			    	priv = catoken.getPrivateKey("ecctest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    try {
			        pub = catoken.getPublicKey("ecctest00001");        
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    // the other keys should still be there
			    priv = catoken.getPrivateKey("ecctest00002");
			    pub = catoken.getPublicKey("ecctest00002");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(384, KeyTools.getKeyLength(pub));
			    String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			    assertEquals(newkeyhash, newkeyhash2);
			    
			    // Create keys using AlgorithmParameterSpec
			    AlgorithmParameterSpec paramspec = KeyTools.getKeyGenSpec(pub);
			    catoken.generateKeyPair(paramspec, "ecctest00003");
			    priv = catoken.getPrivateKey("ecctest00003");
			    pub = catoken.getPublicKey("ecctest00003");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(384, KeyTools.getKeyLength(pub));
			    String newkeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			    // Make sure it's not the same key
			    assertFalse(newkeyhash2.equals(newkeyhash3));

			    // Clean up and delete our generated keys
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00002");
			    catoken.deleteEntry(tokenpin.toCharArray(), "ecctest00003");
			}

	/**
	 * @param catoken
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
	protected void doActivateDeactivate(CryptoToken catoken)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, NoSuchProviderException,
			InvalidAlgorithmParameterException, InvalidKeyException,
			SignatureException, CryptoTokenOfflineException,
			CryptoTokenAuthenticationFailedException {
				// We have not activated the token so status should be offline
			    assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			    assertEquals(getProvider(), catoken.getSignProviderName());
				
			    // First we start by deleting all old entries
			    try {
			    	catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    try {
			        // Generate a key, should not work either
			        catoken.generateKeyPair("1024", "rsatest00001");
			    	assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			    	// NOPMD
			    }
			    catoken.activate(tokenpin.toCharArray());
			    // Should still be ACTIVE now, because we run activate
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			
			    // Generate a key, should work
			    catoken.generateKeyPair("1024", "rsatest00001");
			    PrivateKey priv = catoken.getPrivateKey("rsatest00001");
			    PublicKey pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			
			    // Get a key that does not exist
			    try {
			        pub = catoken.getPublicKey("sdfsdf77474");
			        assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			        assertTrue(e.getMessage().contains("No key with alias 'sdfsdf77474'."));
			    }
			    // We have not set auto activate, so the internal key storage in CryptoToken is emptied
			    catoken.deactivate();
			    try {
			        priv = catoken.getPrivateKey("rsatest00001");
			        assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			        assertEquals(getProvider(), e.getMessage());
			    }
			    try {
			        pub = catoken.getPublicKey("rsatest00001");
			        assertTrue("Should throw", false);
			    } catch (CryptoTokenOfflineException e) {
			        assertEquals(getProvider(), e.getMessage());
			    }
			    // Activate with wrong PIN should not work
			    try {
			        catoken.activate("gfhf56564".toCharArray());
			        assertTrue("should throw", false);
			    } catch (CryptoTokenAuthenticationFailedException e) {
			    	String strsoft = "PKCS12 key store mac invalid - wrong password or corrupted file.";
			    	String strp11 = "Failed to initialize PKCS11 provider slot '1'.";
			        assert(e.getMessage().equals(strsoft)||e.getMessage().equals(strp11));
			    }
			    catoken.activate(tokenpin.toCharArray());
			    priv = catoken.getPrivateKey("rsatest00001");
			    pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			
			    // End by deleting all old entries
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			}

	/**
	 * @param catoken
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
	protected void doAutoActivate(CryptoToken catoken)
			throws CryptoTokenOfflineException, KeyStoreException,
			NoSuchProviderException, NoSuchAlgorithmException,
			CertificateException, IOException, InvalidKeyException,
			SignatureException, CryptoTokenAuthenticationFailedException,
			InvalidAlgorithmParameterException {
				Properties prop = catoken.getProperties();
			    prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);
			    catoken.setProperties(prop);
			    
			    // We have autoactivation, so status should be ACTIVE
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    assertEquals(getProvider(), catoken.getSignProviderName());
			    
			    catoken.deactivate();
			    // It should autoactivate getting status
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    catoken.activate(tokenpin.toCharArray());
			    assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			    
			    // Generate a key
			    catoken.generateKeyPair("1024", "rsatest00001");
			    PrivateKey priv = catoken.getPrivateKey("rsatest00001");
			    PublicKey pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			    // Deactivate
			    catoken.deactivate();
			    // It should autoactivate trying to get keys
			    priv = catoken.getPrivateKey("rsatest00001");
			    pub = catoken.getPublicKey("rsatest00001");
			    KeyTools.testKey(priv, pub, catoken.getSignProviderName());
			    assertEquals(1024, KeyTools.getKeyLength(pub));
			    
			    // End by deleting all old entries
			    catoken.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			}

	protected void doStoreAndLoad(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
	    token.activate(tokenpin.toCharArray());
	    assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
	    token.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
	    
	    // Generate a key
	    token.generateKeyPair("1024", "rsatest00001");
	    PrivateKey priv = token.getPrivateKey("rsatest00001");
	    PublicKey pub = token.getPublicKey("rsatest00001");
	    KeyTools.testKey(priv, pub, token.getSignProviderName());
	    assertEquals(1024, KeyTools.getKeyLength(pub));
	    String pubKHash = CertTools.getFingerprintAsString(pub.getEncoded());
	    assertEquals(111, token.getId()); // What we set in "createCryptoToken"
	    
	    // Serialize the token and re-create it from scratch
	    Properties prop = token.getProperties();
	    byte[] data = token.getTokenData();
	    // prop and data can now be persisted somewhere and retrieved again a week later
	    CryptoToken token2 = CryptoTokenFactory.createCryptoToken(token.getClass().getName(), prop, data, 555);
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
	    token.deleteEntry(tokenpin.toCharArray(), "rsatest00001");
	}

	protected void doGenerateSymKey(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
	    token.activate(tokenpin.toCharArray());
	    assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
	    token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
	    // Generate the symm key
	    token.generateKey("AES", 256, "aestest00001");
	    Key symkey = token.getKey("aestest00001");
	    // Encrypt something with the key, must be multiple of 16 bytes for AES (need to do padding on your own)
	    String input = "1234567812345678"; 
	    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", token.getEncProviderName());
	    IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
	    cipher.init(Cipher.ENCRYPT_MODE, symkey, ivSpec);
	    byte[] cipherText = cipher.doFinal(input.getBytes());
	    // Decrypt
	    cipher.init(Cipher.DECRYPT_MODE, symkey, ivSpec);
	    byte[] plainText = cipher.doFinal(cipherText);
	    assertEquals(input, new String(plainText));
	    
	    // Serialize the token and re-create it from scratch
	    Properties prop = token.getProperties();
	    byte[] data = token.getTokenData();
	    CryptoToken token2 = CryptoTokenFactory.createCryptoToken(token.getClass().getName(), prop, data, 555);
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
//	    KeyPair kp = KeyTools.genKeys("512", "RSA");
//	    Cipher c = Cipher.getInstance("AES/CBC/NoPadding", token.getEncProviderName());
//        c.init( Cipher.WRAP_MODE, symkey2 );
//        byte[] wrappedkey = c.wrap( kp.getPrivate() );
//        Cipher c2 = Cipher.getInstance( "AES/CBC/NoPadding" );
//        c2.init(Cipher.UNWRAP_MODE, symkey2);
//        Key unwrappedkey = c.unwrap(wrappedkey, "RSA", Cipher.PRIVATE_KEY);
//        KeyTools.testKey((PrivateKey)unwrappedkey, kp.getPublic(), "BC");

	    // Clean up by deleting key
	    token.deleteEntry(tokenpin.toCharArray(), "aestest00001");
	}

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

	protected void doExtractKeyFalse(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException {

		Properties prop = token.getProperties();
	    prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(false));
	    token.setProperties(prop);

	    BaseCryptoToken basetoken = (BaseCryptoToken)token;
	    assertFalse(basetoken.doPermitExtractablePrivateKey());
	    
        //create encryption key
        token.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
        token.deleteEntry(tokenpin.toCharArray(), "encryptkeytest001");
        token.generateKey("DESede", 128, "encryptkeytest001");
        
        //create the key pair
        token.generateKeyPair("1024", "extractkeytest001");
        
        //extract the private key
        try {
            token.extractKey("DESede/ECB/PKCS5Padding", "encryptkeytest001", "extractkeytest001");
            assertTrue("Should have received an exception", false);
        } catch (PrivateKeyNotExtractableException e) {
            assertTrue(true);
        }

        token.deleteEntry(tokenpin.toCharArray(), "encryptkeytest001");
        token.deleteEntry(tokenpin.toCharArray(), "extractkeytest001");

	}

	protected void doExtractKey(CryptoToken token) throws InvalidKeyException, CryptoTokenOfflineException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, CryptoTokenAuthenticationFailedException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, PrivateKeyNotExtractableException {

		Properties prop = token.getProperties();
	    prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(true));
	    token.setProperties(prop);

	    BaseCryptoToken basetoken = (BaseCryptoToken)token;
	    assertTrue(basetoken.doPermitExtractablePrivateKey());

        //create encryption key
        token.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
        try {
            token.deleteEntry(tokenpin.toCharArray(), "encryptkeytest001");
            token.deleteEntry(tokenpin.toCharArray(), "extractkeytest001");
    	    //token.generateKey("AES", 256, "encryptkeytest001");
            token.generateKey("DESede", 128, "encryptkeytest001");
            //token.generateKey("DESede", 192, "encryptkeytest001");
            
            //create the key pair
            token.generateKeyPair("512", "extractkeytest001");
            
            //extract the private key
            byte[] wrappedkey = token.extractKey("DESede/ECB/PKCS5Padding", "encryptkeytest001", "extractkeytest001");
            //byte[] wrappedkey = token.extractKey("AES/CBC/NoPadding", "encryptkeytest001", "extractkeytest001");
            
            //get encryption key
            Key encryptionKey = token.getKey("encryptkeytest001");
            
            //unwrap private key and check if it is ok
            Cipher c = Cipher.getInstance( "DESede/ECB/PKCS5Padding" );
            c.init(Cipher.UNWRAP_MODE, encryptionKey);
            
            Key unwrappedkey = c.unwrap(wrappedkey, "RSA", Cipher.PRIVATE_KEY);
            
            assertEquals(token.getPrivateKey("extractkeytest001"), unwrappedkey);
        } finally {
        	token.deleteEntry(tokenpin.toCharArray(), "encryptkeytest001");
        	token.deleteEntry(tokenpin.toCharArray(), "extractkeytest001");
        }
	}

	abstract String getProvider();
}
