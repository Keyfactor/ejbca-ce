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

import java.io.ByteArrayInputStream;
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

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * 
 * @version $Id$
 *
 */
public abstract class CATokenTestBase {

	public static final String tokenpin = "userpin1";


	protected void doCaTokenRSA(CryptoToken cryptoToken) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
		CAToken catoken = new CAToken(cryptoToken);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

			// First we start by deleting all old entries
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00003");

			// Try to delete something that does not exist, it should work without error
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "sdkfjhsdkfjhsd777");

			// We have no keys generated according to the labels above, so the status will be offline
			assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			assertEquals("SHA256WithRSA", catoken.getTokenInfo().getSignatureAlgorithm());
			assertEquals("SHA256WithRSA", catoken.getTokenInfo().getEncryptionAlgorithm());
			assertEquals(getProvider(), catoken.getCryptoToken().getSignProviderName());

			catoken.getCryptoToken().activate(tokenpin.toCharArray());
			// Should still be offline, because we don't have any keys matching our labels
			assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getTokenInfo().getKeySequence());
			// Generate the first key, will get name of the certsign property when generating with renew=false
			// also a encryption key with default alias will be generated
			Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE); // Default sequence is 0
			catoken.generateKeys(tokenpin.toCharArray(), false, true);
			Properties p = catoken.getTokenInfo().getProperties();
			assertEquals("00000", p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY));
			assertEquals("rsatest00000", p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
			assertEquals("rsatest00000", p.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
			assertEquals("rsatest00001", p.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
			assertEquals(null, p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS));
			// Now sequence should be 1, generated and activated new keys
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			// When generating keys with renew = false, we generate initial keys, which means generating the key aliases
			// we have specified for signature and encryption keys
			// After this all needed CAToken keys are generated and status will be active
			assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			PrivateKey priv = null;
			PublicKey pub = null;
			String keyhash = null;
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pub));
			keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			PrivateKey privenc = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			PublicKey pubenc = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			assertEquals(1024, KeyTools.getKeyLength(pubenc));
			assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pubenc));
			KeyTools.testKey(privenc, pubenc, catoken.getCryptoToken().getSignProviderName());
			try {
				KeyTools.testKey(privenc, pub, catoken.getCryptoToken().getSignProviderName());
				assertTrue("Should have thrown because the encryption key and signature key should not be the same", false);
			} catch (InvalidKeyException e) {
				// NOPMD: ignore this is what we want
			}
			try {
				catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this is what we want			
			}
			try {
				catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this is what we want			
			}

			// Generate new keys, moving the old ones to "previous key"
			catoken.generateKeys(tokenpin.toCharArray(), true, true);
			// Now we move away the rsatest0000 key alias from our mappings, so we are now active
			assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
			p = catoken.getTokenInfo().getProperties();
			assertEquals("00001", p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY));
			assertEquals("rsatest0000000002", p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
			assertEquals("rsatest0000000002", p.getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
			assertEquals("rsatest00001", p.getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
			assertEquals("rsatest00000", p.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS));
			assertNull(p.getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
			assertEquals("1024", p.getProperty(CryptoToken.KEYSPEC_PROPERTY));
			String previousSequence = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence));
			// Now sequence should be 2, generated and activated new keys
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse("New kays are same as old keys, should not be...", keyhash.equals(newkeyhash));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(keyhash, previouskeyhash);

			// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
			// Generate new keys, moving the old ones to "previous key"
			catoken.generateKeys(tokenpin.toCharArray(), true, false);
			p = catoken.getTokenInfo().getProperties();
			String previousSequence2 = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(previousSequence, previousSequence2);
			// Now sequence should still be 2, generated but did not activate the new keys
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash, newkeyhash2);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(previouskeyhash, previouskeyhash2);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse(newkeyhash2.equals(nextkeyhash));
			String nextSequence = p.getProperty(CryptoToken.NEXT_SEQUENCE_PROPERTY);
			// Next sequence, for the non-activated key should be 3
			Integer nextseq = seq + 1;
			assertEquals(nextseq, Integer.valueOf(nextSequence));
			// Make sure the properties was set correctly so we did not get the "default" key as next
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			try {
				KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
				assertTrue("Should throw", false);
			} catch (InvalidKeyException e) {
				// NOPMD
			}

			// finally activate the "next key" moving that to current and moving the current to previous
			catoken.activateNextSignKey(tokenpin.toCharArray());
			p = catoken.getTokenInfo().getProperties();
			String previousSequence3 = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			// The former active sequence (2) should have been moved to "previous sequence" now
			assertEquals(seq, Integer.valueOf(previousSequence3));
			assertEquals(nextseq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(nextkeyhash, currentkeyhash);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash2, previouskeyhash3);
			// Next should now return the encryption key instead, since it is the default
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(1024, KeyTools.getKeyLength(pub));
			assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
		} finally {
			// Clean up and delete our generated keys
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00000");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00003");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest0000000002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest0000000003");			
		}
	}

	protected void doCaTokenDSA(CryptoToken cryptoToken) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
		CAToken catoken = new CAToken(cryptoToken);
		// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
		catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
		catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
		catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_DSA);
		catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

		// First we start by deleting all old entries
		catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
		catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00002");
		catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00003");

		// Try to delete something that does not exist, it should work without error
		catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "sdkfjhsdkfjhsd777");

		// We have no keys generated according to the labels above, so the status will be offline
		assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
		assertEquals("SHA1WithDSA", catoken.getTokenInfo().getSignatureAlgorithm());
		assertEquals("SHA256WithRSA", catoken.getTokenInfo().getEncryptionAlgorithm());
		assertEquals(getProvider(), catoken.getCryptoToken().getSignProviderName());

		catoken.getCryptoToken().activate(tokenpin.toCharArray());
		// Should still be offline, because we don't have any keys matching our labels
		assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
		assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getTokenInfo().getKeySequence());
		// Generate the first key, will get name rsatest+nextsequence = rsatest00001
		Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE); // Default sequence is 0
		catoken.generateKeys(tokenpin.toCharArray(), false, true);
		// Now sequence should be 1, generated and activated new keys
		seq += 1;
		assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
		// When generating keys with renew = false, we generate initial keys, which means generating the key aliases
		// we have specified for signature and encryption keys
		// After this all needed CAToken keys are generated and status will be active
		assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
		PrivateKey priv = null;
		PublicKey pub = null;
		priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
		assertEquals(1024, KeyTools.getKeyLength(pub));
		assertEquals("DSA", AlgorithmTools.getKeyAlgorithm(pub));
		// Generate key above should have generated the sign key (DSA) and an encryption key with the alias of the "default" key
		// The encryption key is always RSA and by default 2048
		PrivateKey privenc = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		PublicKey pubenc = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
		assertEquals(2048, KeyTools.getKeyLength(pubenc));
		assertEquals("RSA", AlgorithmTools.getKeyAlgorithm(pubenc));
		KeyTools.testKey(privenc, pubenc, catoken.getCryptoToken().getSignProviderName());
		try {
			KeyTools.testKey(privenc, pub, catoken.getCryptoToken().getSignProviderName());
			assertTrue("Should have thrown because the encryption key and signature key should not be the same", false);
		} catch (InvalidKeyException e) {
			// NOPMD: ignore this is what we want
		}
	}

	protected void doCaTokenECC(CryptoToken cryptoToken) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, IOException,
	CryptoTokenOfflineException, NoSuchProviderException,
	InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
		CAToken catoken = new CAToken(cryptoToken);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);

			// First we start by deleting all old entries
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00003");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");

			// Try to delete something that does not exist, it should work without error
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "sdkfjhsdkfjhsd4447");

			assertEquals("SHA256withECDSA", catoken.getTokenInfo().getSignatureAlgorithm());
			assertEquals("SHA256WithRSA", catoken.getTokenInfo().getEncryptionAlgorithm());
			assertEquals(getProvider(), catoken.getCryptoToken().getSignProviderName());

			catoken.getCryptoToken().activate(tokenpin.toCharArray());
			// Should still be offline, because we don't have any keys matching our labels
			assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus());
			assertEquals(CAToken.DEFAULT_KEYSEQUENCE, catoken.getTokenInfo().getKeySequence());

			// Generate the first key, will get name rsatest+nextsequence = rsatest00001
			Integer seq = Integer.valueOf(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.generateKeys(tokenpin.toCharArray(), false, true);
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			PrivateKey priv = null;
			PublicKey pub = null;
			String keyhash = null;
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			assertEquals("ECDSA", AlgorithmTools.getKeyAlgorithm(pub));
			keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			// There should exist an encryption key when we have generated keys with renew = false
			// Encryption key should be an RSA key with 2048 bit, since signature key is ECDSA
			PublicKey encPub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			assertEquals(2048, KeyTools.getKeyLength(encPub));

			// Generate new keys, moving the old ones to "previous key"
			catoken.generateKeys(tokenpin.toCharArray(), true, true);
			Properties p = catoken.getTokenInfo().getProperties();
			String previousSequence = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence));
			seq += 1;
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse("New kays are same as old keys, should not be...", keyhash.equals(newkeyhash));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(keyhash, previouskeyhash);

			// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
			// Generate new keys, moving the old ones to "previous key"
			catoken.generateKeys(tokenpin.toCharArray(), true, false);
			p = catoken.getTokenInfo().getProperties();
			String previousSequence2 = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(previousSequence, previousSequence2);
			assertEquals(seq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash, newkeyhash2);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(previouskeyhash, previouskeyhash2);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertFalse(newkeyhash2.equals(nextkeyhash));
			String nextSequence = p.getProperty(CryptoToken.NEXT_SEQUENCE_PROPERTY);
			Integer nextseq = seq + 1;
			assertEquals(nextseq, Integer.valueOf(nextSequence));
			// Make sure the properties was set correctly so we did not get the "default" key as next
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);

			// finally activate the "next key" moving that to current and moving the current to previous
			catoken.activateNextSignKey(tokenpin.toCharArray());
			p = catoken.getTokenInfo().getProperties();
			String previousSequence3 = p.getProperty(CryptoToken.PREVIOUS_SEQUENCE_PROPERTY);
			assertEquals(seq, Integer.valueOf(previousSequence3));
			assertEquals(nextseq, Integer.valueOf(catoken.getTokenInfo().getKeySequence()));
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(nextkeyhash, currentkeyhash);
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
			KeyTools.testKey(priv, pub, catoken.getCryptoToken().getSignProviderName());
			assertEquals(256, KeyTools.getKeyLength(pub));
			String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
			assertEquals(newkeyhash2, previouskeyhash3);
			try  {
				catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
				assertTrue("Should have thrown because the key should not exist", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD: ignore this
			}
			// Next should now return the encryption key instead, since it is the default
			// There exist an RSA encryption key
			priv = catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_HARDTOKENENCRYPT);
			KeyTools.testKey(priv, encPub, catoken.getCryptoToken().getSignProviderName());
			// There exist an RSA encryption key
			pub = catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
			assertEquals(2048, KeyTools.getKeyLength(pub));
		} finally {
			// Clean up and delete our generated keys
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00000");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest00003");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");			
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest0000000002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "ecctest0000000003");
		}
	}

	abstract String getProvider();

	protected void doActivateDeactivate(CryptoToken cryptoToken)
	throws KeyStoreException, NoSuchAlgorithmException,
	CertificateException, IOException, CryptoTokenOfflineException,
	NoSuchProviderException, InvalidKeyException, SignatureException,
	CryptoTokenAuthenticationFailedException,
	InvalidAlgorithmParameterException {
		// Remove auto activate
		Properties prop = cryptoToken.getProperties();
		prop.remove(CryptoToken.AUTOACTIVATE_PIN_PROPERTY);
		cryptoToken.setProperties(prop);

		CAToken catoken = new CAToken(cryptoToken);
		try {
			// Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
			catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
			catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
			catoken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
			catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);

			// First we start by deleting all old entries
			try {
				catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
				assertTrue("Should throw", false);
			} catch (CryptoTokenOfflineException e) {
				// NOPMD
			}
			catoken.getCryptoToken().activate(tokenpin.toCharArray());
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00003");

			// Before this there are no keys. 
			catoken.generateKeys(tokenpin.toCharArray(), false, true);
			KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
					catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());

			// We have not set auto activate, so the internal key storage in CryptoToken is emptied
			catoken.getCryptoToken().deactivate();
			try {
				KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
						catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
				assertTrue(false);
			} catch (CryptoTokenOfflineException e) {
				assertEquals(getProvider(), e.getMessage());
			}
			// Activate with wrong PIN should not work
			try {
				catoken.getCryptoToken().activate("foo123".toCharArray());
				assertTrue("should throw", false);
			} catch (CryptoTokenAuthenticationFailedException e) {
				String strsoft = "PKCS12 key store mac invalid - wrong password or corrupted file.";
				String strp11 = "Failed to initialize PKCS11 provider slot '1'.";
				assert(e.getMessage().equals(strsoft)||e.getMessage().equals(strp11));
			}
			catoken.getCryptoToken().activate(tokenpin.toCharArray());
			KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
					catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());

			// Try to generate keys with wrong password
			// The pkcs#11 session is already open and does not care what password we use. 
			// The p11 password is only used by p11 when creating the session. SO we could put wrong pwd here for P11, but not for soft
			try {
				catoken.generateKeys(tokenpin.toCharArray(), false, true);
				KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
						catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
			} catch (CryptoTokenAuthenticationFailedException e) {
				assertTrue("should not throw", false);
			}
		} finally {
			// End by deleting all old entries
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00000");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00002");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00003");					
		}
	}

	protected void doSaveAndLoad(CryptoToken cryptoToken) throws InvalidKeyException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, IOException, IllegalCryptoTokenException {
		CAToken catoken = new CAToken(cryptoToken);
		try {
			catoken.generateKeys("foo123".toCharArray(), false, true);

			KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
			String keyhash = CertTools.getFingerprintAsString(catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());

			HashMap<?, ?> data = (HashMap<?, ?>)catoken.saveData();
			String classpath = (String) data.get(CAToken.CLASSPATH);
			String str = (String)data.get(CAToken.KEYSTORE);
			byte[] keyStoreData = null;
			if (StringUtils.isNotEmpty(str)) {
				keyStoreData =  Base64.decode(str.getBytes());			
			}
			String propertyStr = (String)data.get(CAToken.PROPERTYDATA);
			Properties prop = new Properties();
			if (StringUtils.isNotEmpty(propertyStr)) {
				try {
					// If the input string contains \ (backslash on windows) we must convert it to \\
					// Otherwise properties.load will parse it as an escaped character, and that is not good
					propertyStr = StringUtils.replace(propertyStr, "\\", "\\\\");
					prop.load(new ByteArrayInputStream(propertyStr.getBytes()));
				} catch (IOException e) {
					throw new IllegalCryptoTokenException(e);
				}			
			}
			CryptoToken token = CryptoTokenFactory.createCryptoToken(classpath, prop, keyStoreData, 4711);
			CAToken newcatoken = new CAToken(token);

			KeyTools.testKey(newcatoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), newcatoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());
			String newkeyhash = CertTools.getFingerprintAsString(newcatoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN).getEncoded());
			assertEquals(keyhash, newkeyhash);
		} finally {
			// End by deleting all old entries
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00000");
			catoken.getCryptoToken().deleteEntry(tokenpin.toCharArray(), "rsatest00001");
		}
	}

}
