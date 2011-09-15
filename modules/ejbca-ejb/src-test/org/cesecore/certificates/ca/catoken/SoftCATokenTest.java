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
 * Based on EJBCA version: CATokenContainerTest.java 10288 2010-10-26 11:27:21Z anatom $
 * 
 * @version $Id$
 */
public class SoftCATokenTest extends CATokenTestBase {

    public SoftCATokenTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCATokenRSA() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("rsatest00000", "1024", true);

        doCaTokenRSA(cryptoToken);
    }

    @Test
    public void testCATokenDSA() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("dsatest00000", "1024", true);

        doCaTokenDSA(cryptoToken);
    }

	@Test
    public void testCATokenECC() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("ecctest00000", "secp256r1", true);

        doCaTokenECC(cryptoToken);
    }

    @Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("rsatest00000", "1024", true);

    	doActivateDeactivate(cryptoToken);
    }

	@Test
	public void testDefaultPwd() throws Exception {
		// false parameter means we should enablöe default password
    	CryptoToken cryptoToken = createSoftToken("rsatest00000", "1024", false);

    	CAToken catoken = new CAToken(cryptoToken);
    	
		catoken.generateKeys("foo123".toCharArray(), false, true);
		KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), null);

		// With default pwd deactivate doesn't do anything because the token always auto-activates with the default pwd
		catoken.getCryptoToken().deactivate();
		KeyTools.testKey(catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), null);
	}


	@Test
	public void testSaveAndLoad() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("rsatest00000", "1024", false);

    	doSaveAndLoad(cryptoToken);
	}

	@Test
	public void testDefaultEjbcaSoftTokenProperties() throws Exception {
    	CryptoToken cryptoToken = createSoftToken("rsatest00000", "1024", false);
    	Properties prop = cryptoToken.getProperties();
    	// Default soft token properties in EJBCA
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
    	prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
		cryptoToken.setProperties(prop);
    	CAToken catoken = new CAToken(cryptoToken);
        catoken.generateKeys("foo123".toCharArray(), false, true);
        // Crypto token is not so picky about all aliases being populated
        assertEquals("crypto token status should be active after key generation", CryptoToken.STATUS_ACTIVE, catoken.getCryptoToken().getTokenStatus());
        // CA token requires that all aliases have keys associated with them
        assertEquals("CA token status should be active after key generation", CryptoToken.STATUS_ACTIVE, catoken.getTokenStatus());
	}

	/** When nodefaultpwd == true, the property SoftCryptoToken.NODEFAULTPWD is set in order to avoid 
	 * trying to use default pwd, if pwd is not specified.
	 * Also the auto activation pin is not set when nodefaultpwd == false.
	 * 
	 * @param signAlias
	 * @param keyspec
	 * @param nodefaultpwd
	 * @return
	 */
	private CryptoToken createSoftToken(String signAlias, String keyspec, boolean nodefaultpwd) {
		CryptoToken cryptoToken = SoftCryptoTokenTest.createSoftToken(nodefaultpwd);
    	Properties prop = cryptoToken.getProperties();
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, "rsatest00001"); // does not exist but will soon, after first generate

        // Set key generation property, since we have no old keys to generate the same sort
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, keyspec);
        // Use autoactivation for easy testing
        if (nodefaultpwd) {
        	prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);
        }
        cryptoToken.setProperties(prop);
		return cryptoToken;
	}
    
    String getProvider() {
    	return "BC";
    }
}
