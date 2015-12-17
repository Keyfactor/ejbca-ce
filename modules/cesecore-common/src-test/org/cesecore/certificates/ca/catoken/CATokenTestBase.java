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
package org.cesecore.certificates.ca.catoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * 
 * @version $Id$
 *
 */
public abstract class CATokenTestBase {

	private static final Logger log = Logger.getLogger(CATokenTestBase.class);
	public static final String TOKEN_PIN = PKCS11TestUtils.getPkcs11SlotPin("userpin1");
	private static final String DEFAULT_KEY = "defaultKey ÅaÄÖbåäöc«»©“”nµA";
	protected static final String ENCRYPTION_KEY = "encryptionKey ÅaÄbbÖcccäâãêëẽć©A";

	protected void doCaTokenRSA(String keySpecification, CryptoToken cryptoToken, Properties caTokenProperties) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
		CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
			// First we start by deleting all old entries
            cryptoToken.activate(TOKEN_PIN.toCharArray());
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("rsatest0000"+i);
            }
			// Try to delete something that does not exist, it should work without error
			cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");
            cryptoToken.deactivate();
			// We have no keys generated according to the labels above, so the status will be offline
			assertEquals("Expected CryptoToken to be offline.", CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
			assertEquals("SHA256WithRSA", catoken.getSignatureAlgorithm());
			assertEquals("SHA256WithRSA", catoken.getEncryptionAlgorithm());
			assertEquals(getProvider(), cryptoToken.getSignProviderName());

            assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
			cryptoToken.activate(TOKEN_PIN.toCharArray());
			assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
			assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getKeySequence());
			// Generate the first key, will get name of the certsign property when generating with renew=false
			// also a encryption key with default alias will be generated
			Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE);
			//catoken.generateKeys(cryptoToken, tokenpin.toCharArray(), false, true);
            final String firstSignKeyAlias = catoken.generateNextSignKeyAlias();
            cryptoToken.generateKeyPair(keySpecification, firstSignKeyAlias);
            cryptoToken.generateKeyPair("1024", ENCRYPTION_KEY);
            catoken.activateNextSignKey();
			Properties p = catoken.getProperties();
            assertEquals(null, p.getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
            assertEquals("Expected to use default key.", ENCRYPTION_KEY, catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			assertEquals(CAToken.DEFAULT_KEYSEQUENCE, p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY));
            assertEquals("rsatest0000"+(seq+1), p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
            assertEquals("rsatest0000"+(seq+1), p.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
            assertEquals(ENCRYPTION_KEY, p.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
            assertEquals("rsatest0000"+(seq), p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS));
			// Now sequence should be 1, generated and activated new keys
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
			// When generating keys with renew = false, we generate initial keys, which means generating the key aliases
			// we have specified for signature and encryption keys
			// After this all needed CAToken keys are generated and status will be active
			assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
            PrivateKey priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            PublicKey pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pub));
            String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			PrivateKey privenc = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			PublicKey pubenc = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			assertEquals(1024, KeyTools.getKeyLength(pubenc));
			assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pubenc));
			KeyTools.testKey(privenc, pubenc, cryptoToken.getSignProviderName());
			try {
				KeyTools.testKey(privenc, pub, cryptoToken.getSignProviderName());
				assertTrue("Should have thrown because the encryption key and signature key should not be the same", false);
			} catch (InvalidKeyException e) {
				// NOPMD: ignore this is what we want
			}
			try {
			    cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this is what we want			
			}
			try {
			    cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this is what we want			
			}

			// Generate new keys, moving the old ones to "previous key"
			//catoken.generateKeys(cryptoToken, tokenpin.toCharArray(), true, true);
            final String nextSignKeyAlias = catoken.generateNextSignKeyAlias();
            final PublicKey currentSingKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keySpec = AlgorithmTools.getKeySpecification(currentSingKey);
            cryptoToken.generateKeyPair(keySpec, nextSignKeyAlias);
            catoken.activateNextSignKey();
			// Now we move away the rsatest00001 key alias from our mappings, so we are now active
			assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
			p = catoken.getProperties();
			assertEquals("0000"+(seq), p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY));
            assertEquals("rsatest0000"+(seq+1), p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
            assertEquals("rsatest0000"+(seq+1), p.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
            assertEquals(ENCRYPTION_KEY, p.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
            assertEquals("rsatest0000"+(seq), p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS));
            assertNull(p.getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
			String previousSequence = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence));
			// Now sequence should be 2, generated and activated new keys
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse("New kays are same as old keys, should not be...", keyhash.equals(newkeyhash));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(keyhash, previouskeyhash);

			// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
			// Generate new keys, moving the old ones to "previous key"
            final String nextSignKeyAlias2 = catoken.generateNextSignKeyAlias();
            final PublicKey currentSingKey2 = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keySpec2 = AlgorithmTools.getKeySpecification(currentSingKey2);
            cryptoToken.generateKeyPair(keySpec2, nextSignKeyAlias2);

            p = catoken.getProperties();
			String previousSequence2 = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(previousSequence, previousSequence2);
			// Now sequence should still be 2, generated but did not activate the new keys
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash, newkeyhash2);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(previouskeyhash, previouskeyhash2);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse(newkeyhash2.equals(nextkeyhash));
			String nextSequence = p.getProperty(CATokenConstants.NEXT_SEQUENCE_PROPERTY);
			// Next sequence, for the non-activated key should be 3
			Integer nextseq = seq + 1;
			assertEquals(nextseq, Integer.valueOf(nextSequence));
			// Make sure the properties was set correctly so we did not get the "default" key as next
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			try {
				KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
				assertTrue("Should throw", false);
			} catch (InvalidKeyException e) {
				// NOPMD
			}
			// finally activate the "next key" moving that to current and moving the current to previous
            catoken.activateNextSignKey();
			p = catoken.getProperties();
			String previousSequence3 = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			// The former active sequence (2) should have been moved to "previous sequence" now
			assertEquals(seq, Integer.valueOf(previousSequence3));
			assertEquals(nextseq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(nextkeyhash, currentkeyhash);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash2, previouskeyhash3);
			// Next should now return the encryption key instead, since it is the default
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
		} finally {
			// Clean up and delete our generated keys
            cryptoToken.deleteEntry(ENCRYPTION_KEY);
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("rsatest0000"+i);
            }
		    cryptoToken.deleteEntry("rsatest0000000002");
		    cryptoToken.deleteEntry("rsatest0000000003");			
		}
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
	}

	protected void doCaTokenDSA(String keySpecification, CryptoToken cryptoToken, Properties caTokenProperties) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
		CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
		catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
		// First we start by deleting all old entries
        for (int i=0; i<4; i++) {
            cryptoToken.deleteEntry("dsatest0000"+i);
        }
		// Try to delete something that does not exist, it should work without error
		cryptoToken.deleteEntry("sdkfjhsdkfjhsd777");

		// Even though the token is empty it can still be active
		assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
		assertEquals("SHA1WithDSA", catoken.getSignatureAlgorithm());
		assertEquals("SHA256WithRSA", catoken.getEncryptionAlgorithm());
		assertEquals(getProvider(), cryptoToken.getSignProviderName());
		cryptoToken.activate(TOKEN_PIN.toCharArray());
		assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
		assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getKeySequence());
		// Generate the first key, will get name rsatest+nextsequence = rsatest00001
		Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE);
        final String firstSignKeyAlias = catoken.generateNextSignKeyAlias();
        cryptoToken.generateKeyPair(keySpecification, firstSignKeyAlias);
        cryptoToken.generateKeyPair("1024", ENCRYPTION_KEY);
        catoken.activateNextSignKey();
		// Now sequence should be 1, generated and activated new keys
		seq += 1;
		assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
		// When generating keys with renew = false, we generate initial keys, which means generating the key aliases
		// we have specified for signature and encryption keys
		// After this all needed CAToken keys are generated and status will be active
		assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        PrivateKey priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        PublicKey pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
		KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
		assertEquals(1024, KeyTools.getKeyLength(pub));
		assertEquals("DSA", AlgorithmTools.getKeyAlgorithm(pub));
		// Generate key above should have generated the sign key (DSA) and an encryption key with the alias of the "default" key
		// The encryption key is always RSA and we generate it as 1024 bits to speed up the test
		PrivateKey privenc = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
		PublicKey pubenc = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
		assertEquals(1024, KeyTools.getKeyLength(pubenc));
		assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pubenc));
		KeyTools.testKey(privenc, pubenc, cryptoToken.getSignProviderName());
		try {
			KeyTools.testKey(privenc, pub, cryptoToken.getSignProviderName());
			assertTrue("Should have thrown because the encryption key and signature key should not be the same", false);
		} catch (InvalidKeyException e) {
			// NOPMD: ignore this is what we want
		}
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
	}

	protected void doCaTokenECC(String keySpecification, CryptoToken cryptoToken, Properties caTokenProperties) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
		final CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

			// First we start by deleting all old entries
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("ecctest0000"+i);
            }
			cryptoToken.deleteEntry(ENCRYPTION_KEY);

			// Try to delete something that does not exist, it should work without error
			cryptoToken.deleteEntry("sdkfjhsdkfjhsd4447");

			assertEquals("SHA256withECDSA", catoken.getSignatureAlgorithm());
			assertEquals("SHA256WithRSA", catoken.getEncryptionAlgorithm());
			assertEquals(getProvider(), cryptoToken.getSignProviderName());

			cryptoToken.activate(TOKEN_PIN.toCharArray());
			assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
			assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getKeySequence());

			// Generate the first key, will get name rsatest+nextsequence = rsatest00001
			Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE);
			cryptoToken.generateKeyPair("1024", ENCRYPTION_KEY);
	        final String firstSignKeyAlias = catoken.generateNextSignKeyAlias();
	        cryptoToken.generateKeyPair(keySpecification, firstSignKeyAlias);
	        catoken.activateNextSignKey();
            seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
            PrivateKey priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            PublicKey pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			assertEquals("ECDSA", AlgorithmTools.getKeyAlgorithm(pub));
            String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			// There should exist an encryption key when we have generated keys with renew = false
			// Encryption key should be an RSA key with 2048 bit, since signature key is ECDSA
			PublicKey encPub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			assertEquals(1024, KeyTools.getKeyLength(encPub));

			// Generate new keys, moving the old ones to "previous key"
			final String nextSignKeyAlias2 = catoken.generateNextSignKeyAlias();
            final PublicKey currentSingKey2 = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keySpec2 = AlgorithmTools.getKeySpecification(currentSingKey2);
            log.debug("currentSingKey2: " + currentSingKey2 + " keySpec2: " + keySpec2);
            cryptoToken.generateKeyPair(keySpec2, nextSignKeyAlias2);
            catoken.activateNextSignKey();
			Properties p = catoken.getProperties();
			String previousSequence = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence));
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse("New kays are same as old keys, should not be...", keyhash.equals(newkeyhash));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(keyhash, previouskeyhash);

			// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
			// Generate new keys, moving the old ones to "previous key"
			final String nextSignKeyAlias3 = catoken.generateNextSignKeyAlias();
            final PublicKey currentSingKey3 = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final String keySpec3 = AlgorithmTools.getKeySpecification(currentSingKey3);
            cryptoToken.generateKeyPair(keySpec3, nextSignKeyAlias3);
            p = catoken.getProperties();
			String previousSequence2 = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(previousSequence, previousSequence2);
			assertEquals(seq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash, newkeyhash2);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(previouskeyhash, previouskeyhash2);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse(newkeyhash2.equals(nextkeyhash));
			String nextSequence = p.getProperty(CATokenConstants.NEXT_SEQUENCE_PROPERTY);
			Integer nextseq = seq + 1;
			assertEquals(nextseq, Integer.valueOf(nextSequence));
			// Make sure the properties was set correctly so we did not get the "default" key as next
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));

			// finally activate the "next key" moving that to current and moving the current to previous
			catoken.activateNextSignKey();
			p = catoken.getProperties();
			String previousSequence3 = p.getProperty(CATokenConstants.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence3));
			assertEquals(nextseq, Integer.valueOf(catoken.getKeySequence()));
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(nextkeyhash, currentkeyhash);
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS));
			KeyTools.testKey(priv, pub, cryptoToken.getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash2, previouskeyhash3);
			try  {
				cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT));
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this
			}
			// Next should now return the encryption key instead, since it is the default
			// There exist an RSA encryption key
			priv = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT));
			KeyTools.testKey(priv, encPub, cryptoToken.getSignProviderName());
			// There exist an RSA encryption key
			pub = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
			assertEquals(1024, KeyTools.getKeyLength(pub));
		} finally {
			// Clean up and delete our generated keys
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("ecctest0000"+i);
            }
			cryptoToken.deleteEntry("rsatest00001");			
			cryptoToken.deleteEntry("ecctest0000000002");
			cryptoToken.deleteEntry("ecctest0000000003");
		}
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
	}

	abstract String getProvider();

	protected void doActivateDeactivate(String keySpecification, CryptoToken cryptoToken, Properties caTokenProperties)
	throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException, CryptoTokenOfflineException,
	NoSuchProviderException, InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
		// Remove auto activate
		Properties prop = cryptoToken.getProperties();
		prop.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
		cryptoToken.setProperties(prop);

		CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

			// First we start by deleting all old entries
			try {
				cryptoToken.deleteEntry("rsatest00001");
				assertTrue("Should throw", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD
			}
			cryptoToken.activate(TOKEN_PIN.toCharArray());
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("rsatest0000"+i);
            }
			// Before this there are no keys. 
            final String nextSignKeyAlias = catoken.generateNextSignKeyAlias();
            cryptoToken.generateKeyPair(keySpecification, nextSignKeyAlias);
            catoken.activateNextSignKey();
			KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
					cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), cryptoToken.getSignProviderName());

			// We have not set auto activate, so the internal key storage in CryptoToken is emptied
			cryptoToken.deactivate();
			try {
				KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
						cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), cryptoToken.getSignProviderName());
				assertTrue(false);
			} catch (CryptoTokenOfflineException e) {
                assertEquals("Can not instantiate "+getProvider()+". keyStore (111) == null.", e.getMessage());
			}
			// Activate with wrong PIN should not work
			try {
				cryptoToken.activate((TOKEN_PIN+"x").toCharArray());
				assertTrue("should throw", false);
			} catch (CryptoTokenAuthenticationFailedException e) {
				String strsoft = "PKCS12 key store mac invalid - wrong password or corrupted file.";
				String strp11 = "Failed to initialize PKCS11 provider slot '1'.";
				assert(e.getMessage().equals(strsoft)||e.getMessage().equals(strp11));
			}
			cryptoToken.activate(TOKEN_PIN.toCharArray());
			KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
					cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), cryptoToken.getSignProviderName());
		} finally {
			// End by deleting all old entries
            cryptoToken.activate(TOKEN_PIN.toCharArray());
            for (int i=0; i<4; i++) {
                cryptoToken.deleteEntry("rsatest0000"+i);
            }
		}
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
	}

	protected void doSaveAndLoad(String keySpecification, CryptoToken cryptoToken, Properties caTokenProperties) throws InvalidKeyException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, IOException, IllegalCryptoTokenException {
        log.trace(">" + Thread.currentThread().getStackTrace()[1].getMethodName());
		CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
		try {
		    cryptoToken.activate(TOKEN_PIN.toCharArray());
		    cryptoToken.generateKeyPair(keySpecification, DEFAULT_KEY);
		    catoken.setNextCertSignKey(DEFAULT_KEY);
		    catoken.activateNextSignKey();
		    PublicKey publicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
		    KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
			        publicKey, cryptoToken.getSignProviderName());
			String keyhash = CertTools.getFingerprintAsString(publicKey.getEncoded());
			HashMap<?, ?> data = (HashMap<?, ?>)catoken.saveData();
            CAToken newcatoken = new CAToken(data);
			assertEquals(cryptoToken.getId(), newcatoken.getCryptoTokenId());
			PublicKey newPublicKey = cryptoToken.getPublicKey(newcatoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
			KeyTools.testKey(cryptoToken.getPrivateKey(newcatoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
			        newPublicKey, cryptoToken.getSignProviderName());
			String newkeyhash = CertTools.getFingerprintAsString(newPublicKey.getEncoded());
			assertEquals(keyhash, newkeyhash);
		} finally {
			// End by deleting all old entries
		    cryptoToken.activate(TOKEN_PIN.toCharArray());
			cryptoToken.deleteEntry("rsatest00000");
			cryptoToken.deleteEntry("rsatest00001");
		}
        log.trace("<" + Thread.currentThread().getStackTrace()[1].getMethodName());
	}
}
