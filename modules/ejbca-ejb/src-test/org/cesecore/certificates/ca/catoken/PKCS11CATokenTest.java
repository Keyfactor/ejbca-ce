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

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.PKCS11CryptoTokenTest;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Test;

/**
 * Tests PKCS11 keystore crypto token. To run this test a slot 1 must exist on the hsm, with a user with user pin "userpin1" that can use the slot.
 * 
 * Based on EJBCA version: CATokenContainerTest.java 10288 2010-10-26 11:27:21Z anatom $
 * 
 * @version $Id: PKCS11CATokenTest.java 389 2011-03-01 14:56:15Z tomas $
 */
public class PKCS11CATokenTest extends CATokenTestBase {

    public static final String tokenpin = "userpin1";

    public PKCS11CATokenTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void testCATokenRSA() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token("rsatest00000", "1024");

        doCaTokenRSA(cryptoToken);
    }

	@Test
    public void testCATokenECC() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token("ecctest00000", "secp256r1");

        doCaTokenECC(cryptoToken);
    }

    @Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token("rsatest00000", "1024");

    	doActivateDeactivate(cryptoToken);
    }

	@Test
	public void testSaveAndLoad() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token("rsatest00000", "1024");

    	doSaveAndLoad(cryptoToken);
	}

	private CryptoToken createPKCS11Token(String signAlias, String keyspec) {
		CryptoToken cryptoToken = PKCS11CryptoTokenTest.createPKCS11Token();
    	Properties prop = cryptoToken.getProperties();
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        prop.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, "rsatest00001"); // does not exist but will soon, after first generate

        // Set key generation property, since we have no old keys to generate the same sort
        prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, keyspec);
        // Use autoactivation for easy testing
        prop.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenpin);
        cryptoToken.setProperties(prop);
		return cryptoToken;
	}

    String getProvider() {
    	return PKCS11CryptoTokenTest.getHSMProvider();
    }
}
