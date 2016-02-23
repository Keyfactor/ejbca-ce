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

import java.util.Properties;

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.SoftCryptoTokenTest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests PKCS11 keystore crypto token. To run this test a slot 1 must exist on the hsm, with a user with user pin "userpin1" that can use the slot.
 * 
 * @version $Id$
 */
public class SoftCATokenTest extends CATokenTestBase {

    public SoftCATokenTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCATokenRSA() throws Exception {
        CryptoToken cryptoToken = createSoftToken(false);
        doCaTokenRSA("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

    @Test
    public void testCATokenDSA() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(true);
        doCaTokenDSA("DSA1024", cryptoToken, getCaTokenProperties("dsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
    public void testCATokenECC() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(true);
        doCaTokenECC("secp256r1", cryptoToken, getCaTokenProperties("ecctest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

    @Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(true);
    	doActivateDeactivate("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
	public void testDefaultPwd() throws Exception {
		// false parameter means we should enable default password
    	CryptoToken cryptoToken = createSoftToken(true);
    	CAToken catoken = new CAToken(cryptoToken.getId(), getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    	cryptoToken.activate(TOKEN_PIN.toCharArray());
        cryptoToken.generateKeyPair("1024", "rsatest" + CAToken.DEFAULT_KEYSEQUENCE);
		KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
		        cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), null);
		// With auto-activate, deactivate doesn't do anything because the token always auto-activates with the default pwd
		cryptoToken.deactivate();
		KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
		        cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), null);
	}

	@Test
	public void testSaveAndLoad() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(false);
    	doSaveAndLoad("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
	}

	@Test
	public void testDefaultEjbcaSoftTokenProperties() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(false);
        cryptoToken.activate(TOKEN_PIN.toCharArray());
        cryptoToken.generateKeyPair("1024", CAToken.SOFTPRIVATESIGNKEYALIAS);
        // Crypto token is not so picky about all aliases being populated
        assertEquals("crypto token status should be active after key generation", CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
	}

	@Test
    public void testTokenStatusDifferentAliases() throws Exception {
	    final CryptoToken cryptoToken = createSoftToken(true);
	    final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, "testAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, ENCRYPTION_KEY);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, "deletedAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, "anotherDeletedAlias");
        final CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(true, cryptoToken));
        cryptoToken.generateKeyPair("512", "testAlias");
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(true, cryptoToken));
        cryptoToken.generateKeyPair("512", "signAlias");
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(true, cryptoToken));
        cryptoToken.generateKeyPair("512", ENCRYPTION_KEY);
        // Note that the next and previous key mappings should be ignored
        assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus(true, cryptoToken));
	}
	
    @Test
    public void testTokenStatusCommonAliases() throws Exception {
        final CryptoToken cryptoToken = createSoftToken(false);
        cryptoToken.activate(TOKEN_PIN.toCharArray());
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, "signAlias");
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, "signAlias");
        final CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(true, cryptoToken));
        cryptoToken.generateKeyPair("512", "signAlias");
        // Note that the next and previous key mappings should be ignored
        assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus(true, cryptoToken));
        cryptoToken.deactivate();
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(false, cryptoToken));
        assertEquals(CryptoToken.STATUS_OFFLINE, catoken.getTokenStatus(true, cryptoToken));
    }
    
	/** When nodefaultpwd == true, the property SoftCryptoToken.NODEFAULTPWD is set in order to avoid 
	 * trying to use default pwd, if pwd is not specified.
	 * Also the auto activation pin is not set when nodefaultpwd == false.
	 * 
	 * @param useAutoActivationPin
	 * @return
	 */
	private CryptoToken createSoftToken(boolean useAutoActivationPin) {
		CryptoToken cryptoToken = SoftCryptoTokenTest.createSoftToken(true);
		Properties cryptoTokenProperties = cryptoToken.getProperties();
        // Use autoactivation for easy testing
        if (useAutoActivationPin) {
        	cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, TOKEN_PIN);
        }
        cryptoToken.setProperties(cryptoTokenProperties);
		return cryptoToken;
	}
	
	private Properties getCaTokenProperties(final String signAlias) {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, ENCRYPTION_KEY); // does not exist but will soon, after first generate
        return caTokenProperties;
	}
    
    String getProvider() {
    	return "BC";
    }
}
