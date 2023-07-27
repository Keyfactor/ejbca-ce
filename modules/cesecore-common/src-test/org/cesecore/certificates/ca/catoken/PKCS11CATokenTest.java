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


import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.util.Properties;

import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Tests PKCS11 keystore crypto token. To run this test a slot 1 must exist on the hsm, with a user with user pin "userpin1" that can use the slot.
 *
 * @version $Id$
 */
public class PKCS11CATokenTest extends CATokenTestBase {

    public PKCS11CATokenTest() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void checkPkcs11DriverAvailable() {
        // Skip test if no PKCS11 driver is installed
        assumeTrue("No PKCS#11 library configured", PKCS11TestUtils.getHSMLibrary() != null);
        assumeTrue("No PKCS#11 Provider configured", PKCS11TestUtils.getHSMProvider() != null);
    }

    @Test
    public void testCATokenRSA() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token(false);
        doCaTokenRSA("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

    @Test
    public void testCATokenECCprime() throws Exception {
        CryptoToken cryptoToken = createPKCS11Token(true);
        // "prime256v1" is an alias for "secp256r1" and NIST's "P-256"
        doCaTokenECC("prime256v1", cryptoToken, getCaTokenProperties("ecctest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
    public void testCATokenECCsecp() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token(true);
        doCaTokenECC("secp256r1", cryptoToken, getCaTokenProperties("ecctest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

    @Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token(true);
    	doActivateDeactivate("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
    }

	@Test
	public void testSaveAndLoad() throws Exception {
    	CryptoToken cryptoToken = createPKCS11Token(true);
    	doSaveAndLoad("1024", cryptoToken, getCaTokenProperties("rsatest" + CAToken.DEFAULT_KEYSEQUENCE));
	}

	private CryptoToken createPKCS11Token(boolean useAutoActivationPin) throws NoSuchSlotException {
		CryptoToken cryptoToken = createPKCS11Token();
    	Properties cryptoTokenProperties = cryptoToken.getProperties();
    	if (useAutoActivationPin) {
            cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, CATokenTestBase.TOKEN_PIN);
        }
        cryptoToken.setProperties(cryptoTokenProperties);
		return cryptoToken;
	}

	private Properties getCaTokenProperties(String signAlias) {
	    Properties caTokenProperties = new Properties();
	    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, signAlias); // does not exist and never will, will be moved to new keys
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, ENCRYPTION_KEY); // does not exist but will soon, after first generate
        return caTokenProperties;
	}

    @Override
    String getProvider() {
    	return PKCS11TestUtils.getHSMProvider();
    }
    
    private static CryptoToken createPKCS11Token() throws NoSuchSlotException {
        return createPKCS11TokenWithAttributesFile(null, null, true);
    }

    private static CryptoToken createPKCS11TokenWithAttributesFile(String file, String tokenName, boolean extractable) throws NoSuchSlotException {
        Properties prop = new Properties();
        String hsmlib = PKCS11TestUtils.getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, PKCS11TestUtils.getPkcs11SlotValue());
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, PKCS11TestUtils.getPkcs11SlotType().getKey());
        if (file != null) {
            prop.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, file);
        }
        if (tokenName != null) {
            prop.setProperty(PKCS11CryptoToken.TOKEN_FRIENDLY_NAME, tokenName);
        }
        if (extractable){
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "True");
        } else {
            prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        }
        CryptoToken catoken = CryptoTokenFactory.createCryptoToken(PKCS11CryptoToken.class.getName(), prop, null, 111, "P11 CryptoToken");
        return catoken;
    }
}
