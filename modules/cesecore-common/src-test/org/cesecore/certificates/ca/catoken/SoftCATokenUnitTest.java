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


import java.util.Properties;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Tests soft keystore CA tokens.
 */
public class SoftCATokenUnitTest extends CATokenTestBase {

    public SoftCATokenUnitTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCATokenRSA() throws Exception {
        CryptoToken cryptoToken = createSoftToken(false);
        doCaTokenRSA("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
    public void testCATokenECC() throws Exception {
    	CryptoToken cryptoToken = createSoftToken(true);
        doCaTokenECC("secp256r1", cryptoToken, getCaTokenProperties("ecctest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
	public void testCATokenFalcon() throws Exception {
	    CryptoToken cryptoToken = createSoftToken(true);
	    doCaTokenFalcon("FALCON-512", cryptoToken, getCaTokenProperties("falcontest" + CAToken.DEFAULT_KEYSEQUENCE));
	}

	@Test
    public void testCATokenMLDSA() throws Exception {
        CryptoToken cryptoToken = createSoftToken(true);
        doCaTokenMLDSA("ML-DSA-44", cryptoToken, getCaTokenProperties("ml-dsa-test" + CAToken.DEFAULT_KEYSEQUENCE));
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
        Properties prop = new Properties();
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(true));
        CryptoToken cryptoToken;
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), prop, null, 111, "Soft CryptoToken");
        } catch (NoSuchSlotException e) {
            throw new RuntimeException("Attempted to find a slot for a soft crypto token. This should not happen.");
        }
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

    @Override
    String getProvider() {
    	return "BC";
    }

}
