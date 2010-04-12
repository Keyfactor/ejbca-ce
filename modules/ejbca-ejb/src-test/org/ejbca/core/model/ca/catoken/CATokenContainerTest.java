/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.catoken;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;

import junit.framework.TestCase;

import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Tests soft keystore CA token container
 * 
 * @author tomas
 * @version $Id$
 */
public class CATokenContainerTest extends TestCase {

	public CATokenContainerTest() {
		CryptoProviderTools.installBCProvider();
	}
	
	public void test01SoftCAToken() throws Exception {
		final String tokenpin = "foo123";
		
		SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
		catokeninfo.setSignKeySpec("1024");
		catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
		catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
		catokeninfo.setEncKeySpec("1024");
		catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
		catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        // We need an auto activation PIN in order to test the token in a non-jee environment due to getting of default pwd in SoftCAToken.init()
		Properties prop = catokeninfo.getPropertiesAsClass();
		prop.setProperty(ICAToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        prop.store(out, null);
		catokeninfo.setProperties(out.toString());

		CATokenContainerImpl catoken = new CATokenContainerImpl(catokeninfo, 666);
		assertEquals(CATokenConstants.CATOKENTYPE_P12, catoken.getCATokenType());
        assertEquals("SHA256WithRSA", catoken.getCATokenInfo().getSignatureAlgorithm());
        assertEquals("SHA256WithRSA", catoken.getCATokenInfo().getEncryptionAlgorithm());        

		catoken.activate(tokenpin);
		assertEquals("BC", catoken.getProvider());
		boolean thrown = false;
		try {
			catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);			
		} catch (CATokenOfflineException e) {
			thrown = true;
		}
		assertTrue(thrown);
		
		// Generate new keys, simply...
		assertEquals(CATokenConstants.DEFAULT_KEYSEQUENCE, catoken.getCATokenInfo().getKeySequence());
		Integer seq = Integer.valueOf(CATokenConstants.DEFAULT_KEYSEQUENCE);
		catoken.generateKeys(tokenpin, false, true);
		seq += 1;
		assertEquals(seq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence()));
		thrown = false;
		PrivateKey priv = null;
		PublicKey pub = null;
		String keyhash = null;
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		keyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		
		// Generate new keys, moving the old ones to "previous key"
		catoken.generateKeys(tokenpin, true, true);
		Properties p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(seq, Integer.valueOf(previousSequence));
		seq += 1;
		assertEquals(seq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence()));
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String newkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertFalse(keyhash.equals(newkeyhash));
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(keyhash, previouskeyhash);
		
		// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
		// Generate new keys, moving the old ones to "previous key"
		catoken.generateKeys(tokenpin, true, false);
		p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence2 = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(previousSequence, previousSequence2);
		assertEquals(seq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence()));
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String newkeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(newkeyhash, newkeyhash2);
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(previouskeyhash, previouskeyhash2);
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertFalse(newkeyhash2.equals(nextkeyhash));
		String nextSequence = p.getProperty(ICAToken.NEXT_SEQUENCE_PROPERTY);
		Integer nextseq = seq+1;
		assertEquals(nextseq, Integer.valueOf(nextSequence));
		// Make sure the properties was set correctly so we did not get the "default" key as next
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
		thrown = false;
		try {
			KeyTools.testKey(priv, pub, catoken.getProvider());
		} catch (InvalidKeyException e) {
			thrown = true;
		}
		assertTrue(thrown);

		// finally activate the "next key" moving that to current and moving the current to previous
		catoken.activateNextSignKey(tokenpin);
		p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence3 = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(seq, Integer.valueOf(previousSequence3));
		assertEquals(nextseq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence()));
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(nextkeyhash, currentkeyhash);
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(newkeyhash2, previouskeyhash3);
		thrown = false;
		// Next should now return the encryption key instead, since it is the default
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		
	}

	
	/*
	public void test02PKCS11ProtectServerCATokenEcdsa() throws Exception {
		final String tokenpin = "foo123";
		
		HardCATokenInfo catokeninfo = new HardCATokenInfo();
		catokeninfo.setSignatureAlgorithm(CATokenConstants.SIGALG_SHA256_WITH_ECDSA);
		catokeninfo.setEncryptionAlgorithm(CATokenConstants.SIGALG_SHA256_WITH_ECDSA);
        // We need an auto activation PIN in order to test the token in a non-jee environment due to getting of default pwd in SoftCAToken.init()
		Properties prop = catokeninfo.getPropertiesAsClass();
		prop.setProperty(PKCS11CAToken.ATTRIB_LABEL_KEY, "/home/tomas/Dev/workspace/slot3p11.cfg");
		prop.setProperty(PKCS11CAToken.SHLIB_LABEL_KEY, "/opt/ETcpsdk/lib/linux-x86_64/libcryptoki.so");
		prop.setProperty(KeyStrings.CAKEYPURPOSE_CERTSIGN_STRING, "ecc00001");
		prop.setProperty(KeyStrings.CAKEYPURPOSE_CRLSIGN_STRING, "ecc00001");
		prop.setProperty(KeyStrings.CAKEYPURPOSE_DEFAULT_STRING, "rsa1024");
		prop.setProperty(PKCS11CAToken.SLOT_LABEL_KEY, "3");		
		prop.setProperty(ICAToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);		
        StringWriter sw = new StringWriter();
        prop.store(sw, null);
		catokeninfo.setProperties(sw.toString());
        catokeninfo.setClassPath(PKCS11CAToken.class.getName());

		CATokenContainerImpl catoken = new CATokenContainerImpl(catokeninfo, 666);
		assertEquals(CATokenConstants.CATOKENTYPE_HSM, catoken.getCATokenType());
        assertEquals("SHA256withECDSA", catoken.getCATokenInfo().getSignatureAlgorithm());

		catoken.activate(tokenpin);
		assertEquals("SunPKCS11-libcryptoki.so-slot3", catoken.getProvider());
		PrivateKey priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);			
		PublicKey pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);			
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String keyhash1 = CertTools.getFingerprintAsString(pub.getEncoded());

		// Generate new keys, moving the old ones to "previous key"
		assertEquals(CATokenConstants.DEFAULT_KEYSEQUENCE, catoken.getCATokenInfo().getKeySequence());
		Integer seq = Integer.valueOf(CATokenConstants.DEFAULT_KEYSEQUENCE);
		catoken.generateKeys(tokenpin, true, true);
		Properties p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(seq, Integer.valueOf(previousSequence));
		seq += 1;
		assertEquals(seq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence()));
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String keyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertFalse(keyhash1.equals(keyhash2));		
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(keyhash1, previouskeyhash);

		// Generate new keys, not activating them, this should create a "next key", keeping the current and previous as they are
		// Generate new keys, moving the old ones to "previous key"
		catoken.generateKeys(tokenpin, true, false);
		p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence2 = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(previousSequence, previousSequence2); // Since we did not activate the keys, the old sequence is still the old sequence
		assertEquals(seq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence())); // and the same sequence is used
		String nextSequence = p.getProperty(ICAToken.NEXT_SEQUENCE_PROPERTY);
		Integer nextseq = seq+1;
		assertEquals(nextseq, Integer.valueOf(nextSequence)); // next sequence is set though
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String keyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(keyhash2, keyhash3); // Still the same signature keys as before
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(previouskeyhash, previouskeyhash2); // Still the same previous key hash
		// We should in addition to active and previous keys have some next keys
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String nextkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertFalse(keyhash3.equals(nextkeyhash));
		// Make sure the properties was set correctly so we did not get the "default" key as next
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
		boolean thrown = false;
		try {
			KeyTools.testKey(priv, pub, catoken.getProvider());
		} catch (InvalidKeyException e) {
			thrown = true;
		}
		assertTrue(thrown);

		// finally activate the "next key" moving that to current and moving the current to previous
		catoken.activateNextSignKey(tokenpin);
		p = catoken.getCATokenInfo().getPropertiesAsClass();
		String previousSequence3 = p.getProperty(ICAToken.PREVIOUS_SEQUENCE_PROPERTY);
		assertEquals(seq, Integer.valueOf(previousSequence3)); // previous sequence should be the one that was active before
		assertEquals(nextseq, Integer.valueOf(catoken.getCATokenInfo().getKeySequence())); // the one that was next before should be the active one now
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String currentkeyhash = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(nextkeyhash, currentkeyhash); // next key from before is currnet key now
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS);
		KeyTools.testKey(priv, pub, catoken.getProvider());
		String previouskeyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
		assertEquals(keyhash3, previouskeyhash3); // the active from before is moved to previous now
		// Next should now return the encryption key instead, since it is the default, and we don't have any "next" key anymore
		priv = catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN_NEXT);
		pub = catoken.getPublicKey(SecConst.CAKEYPURPOSE_KEYENCRYPT);
		KeyTools.testKey(priv, pub, catoken.getProvider());
	}
*/
}
