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

import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Tests soft keystore crypto token
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
        doCryptoTokenECCAndPQ(catoken, "secp256r1", 256, "secp384r1", 384);
    }

	@Test
	public void testCryptoTokenED() throws Exception {
	    CryptoToken catoken = createSoftToken(true);
	    doCryptoTokenECCAndPQ(catoken, "Ed25519", 255, "Ed448", 448);
	}

	@Test
	public void testCryptoTokenFalcon() throws Exception {
	    CryptoToken catoken512 = createSoftToken(true);
	    doCryptoTokenECCAndPQ(catoken512, "FALCON-512", 128, "FALCON-512", 128);
        CryptoToken catoken1024 = createSoftToken(true);
        doCryptoTokenECCAndPQ(catoken1024, "FALCON-1024", 256, "FALCON-1024", 256);
	}
	
    @Test
    public void testCryptoTokenDilithium() throws Exception {
        CryptoToken catoken2 = createSoftToken(true);
        doCryptoTokenECCAndPQ(catoken2, "DILITHIUM2", 128, "DILITHIUM2", 128);
        CryptoToken catoken3 = createSoftToken(true);
        doCryptoTokenECCAndPQ(catoken3, "DILITHIUM3", 192, "DILITHIUM3", 192);
        CryptoToken catoken5 = createSoftToken(true);
        doCryptoTokenECCAndPQ(catoken5, "DILITHIUM5", 256, "DILITHIUM5", 256);
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
	public void testWontWorkUnactivated() throws Exception {
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
	}

	@Override
	public String getProvider() {
		return BouncyCastleProvider.PROVIDER_NAME;
	}

	public static CryptoToken createSoftToken() {
        return createSoftToken(true);
	}


    public static CryptoToken createSoftToken(boolean extractable) {
		Properties prop = new Properties();
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

}
