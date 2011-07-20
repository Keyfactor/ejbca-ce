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
import java.util.Properties;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests soft keystore crypto token
 * 
 * Based on EJBCA version: 
 *      CATokenContainerTest.java 10288 2010-10-26 11:27:21Z anatom $
 * Based on cesecore version:
 *       SoftCryptoTokenTest.java 790 2011-05-16 14:45:05Z johane
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
        doCryptoTokenECC(catoken);
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
    	CryptoToken catoken = createSoftToken(true);
    	// Should not work, we need to activate
    	try {
    		catoken.generateKeyPair("1024", "foo");
    		assertTrue("Should throw", false);
    	} catch (CryptoTokenOfflineException e) {
    		// NOPMD
    	}
		catoken.activate("bar123".toCharArray());
		catoken.generateKeyPair("1024", "foo");
		KeyTools.testKey(catoken.getPrivateKey("foo"), catoken.getPublicKey("foo"), null);

		// Use default password
    	catoken = createSoftToken(false);
    	// Should work, auto-password
    	catoken.generateKeyPair("1024", "foo");
		KeyTools.testKey(catoken.getPrivateKey("foo"), catoken.getPublicKey("foo"), null);
    	catoken.deactivate();
    	// Should still work, auto-password
    	catoken.generateKeyPair("1024", "foo");
		KeyTools.testKey(catoken.getPrivateKey("foo"), catoken.getPublicKey("foo"), null);
		// Should not work, wrong password, default is foo123
		try {
			catoken.activate("bar123".toCharArray());
			assertTrue("should throw", false);
		} catch (CryptoTokenAuthenticationFailedException e) {
			// NOPMD
		}
		catoken.activate("foo123".toCharArray());
		catoken.generateKeyPair("1024", "foo");
		KeyTools.testKey(catoken.getPrivateKey("foo"), catoken.getPublicKey("foo"), null);

	}
	
	@Override
	String getProvider() {
		return "BC";
	}

	public static CryptoToken createSoftToken(boolean nodefaultpwd) {
		Properties prop = new Properties();
		if (nodefaultpwd) {
			prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(nodefaultpwd));
		}
        CryptoToken catoken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 111);
		return catoken;
	}
	
	
	@Test
	public void testExtractKeyFalse() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, CryptoTokenOfflineException, IOException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException{
    	CryptoToken token = createSoftToken(true);
		doExtractKeyFalse(token);
	}
	
	
	@Test
	public void testExtractKey() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException, SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, IOException, PrivateKeyNotExtractableException{
    	CryptoToken token = createSoftToken(true);
		doExtractKey(token);	    
	}
}
