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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests soft keystore crypto token
 *
 * @version $Id$
 */
public class SoftCryptoTokenTest extends CryptoTokenTestBase {

	public SoftCryptoTokenTest() {
		CryptoProviderTools.installBCProvider();
	}

    @Test
    public void testCryptoTokenRSA() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
        doCryptoTokenRSA(catoken);
    }

	@Test
    public void testCryptoTokenECC() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
        doCryptoTokenECC(catoken, "secp256r1", 256, "secp384r1", 384);
    }

	@Test
    public void testCryptoTokenECCImplicitlyCA() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
        doCryptoTokenECC(catoken, "implicitlyCA", 0, "prime192v1", 192);
    }

	@Test
    public void testCryptoTokenDSA() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
        doCryptoTokenDSA(catoken);
    }

	@Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
        doActivateDeactivate(catoken);
    }

	@Test
    public void testAutoActivate() throws Exception {
    	CryptoToken catoken = createSoftToken(true);
    	doAutoActivate(catoken);
    }

	@Test
    public void testStoreAndLoad() throws Exception {
    	CryptoToken token = createSoftToken(true);
    	doStoreAndLoad(token);
	}

	@Test
    public void testGenerateSymKey() throws Exception {
    	CryptoToken token = createSoftToken(true);
    	doGenerateSymKey(token);
	}

	@Test
	public void testDefaultPwdOrNot() throws Exception {
    	final CryptoToken cryptoToken1 = createSoftToken(true);
    	// Should not work, we need to activate
    	try {
    		cryptoToken1.generateKeyPair("1024", "foo");
    		assertTrue("Should throw", false);
    	} catch (CryptoTokenOfflineException e) {
    		// NOPMD
    	}
		cryptoToken1.activate("bar123".toCharArray());
		cryptoToken1.generateKeyPair("1024", "foo");
		KeyTools.testKey(cryptoToken1.getPrivateKey("foo"), cryptoToken1.getPublicKey("foo"), null);

		// Use default password
		final CryptoToken cryptoToken2 = createSoftToken(false);
    	// Should work, auto-password
    	cryptoToken2.generateKeyPair("1024", "foo");
		KeyTools.testKey(cryptoToken2.getPrivateKey("foo"), cryptoToken2.getPublicKey("foo"), null);
    	cryptoToken2.deactivate();
    	// Should still work, auto-password
    	cryptoToken2.generateKeyPair("1024", "foo");
		KeyTools.testKey(cryptoToken2.getPrivateKey("foo"), cryptoToken2.getPublicKey("foo"), null);
        // Should work token is already (auto) active
        cryptoToken2.activate("bar123".toCharArray());
		cryptoToken2.activate("foo123".toCharArray());
		cryptoToken2.generateKeyPair("1024", "foo");
		KeyTools.testKey(cryptoToken2.getPrivateKey("foo"), cryptoToken2.getPublicKey("foo"), null);
	}

	@Override
	String getProvider() {
		return "BC";
	}

	public static CryptoToken createSoftToken(boolean nodefaultpwd) {
        return createSoftToken(nodefaultpwd, true);
	}


    public static CryptoToken createSoftToken(boolean nodefaultpwd, boolean extractable) {
		Properties prop = new Properties();
		if (nodefaultpwd) {
			prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(nodefaultpwd));
		}
        if(extractable){
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(true));
        } else {
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(false));
        }
        CryptoToken catoken;
        try {
            catoken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 111, "Soft CryptoToken");
        } catch (NoSuchSlotException e) {
            throw new RuntimeException("Attempted to find a slot for a soft crypto token. This should not happen.");
        }
		return catoken;
	}


	@Test
	public void testExtractKeyFalse() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, CryptoTokenOfflineException, IOException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException {
    	CryptoToken token = createSoftToken(true, false);
		doExtractKeyFalse(token);
	}


	@Test
	public void testExtractKey() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException, SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, IOException, PrivateKeyNotExtractableException, BadPaddingException, InvalidKeySpecException{
    	CryptoToken token = createSoftToken(true, true);
		doExtractKey(token);
	}
}
