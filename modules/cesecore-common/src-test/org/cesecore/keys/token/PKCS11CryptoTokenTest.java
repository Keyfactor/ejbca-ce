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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.Security;
import java.util.Properties;

import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests PKCS11 keystore crypto token. To run this test a slot 1 must exist on the hsm, with a user with user pin "userpin1" that can use the slot.
 *
 * @version $Id$
 */
public class PKCS11CryptoTokenTest extends CryptoTokenTestBase {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @After
    public void tearDown() {
        // Make sure we remove the provider after one test, so it is not still there affecting the next test
        Security.removeProvider(getProvider());
    }

    @Test
    public void testCryptoTokenRSA() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doCryptoTokenRSA(catoken);
    }

	@Test
    public void testCryptoTokenECC() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doCryptoTokenECC(catoken, "secp256r1", 256, "secp384r1", 384);
    }

	@Test
    public void testActivateDeactivate() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
        doActivateDeactivate(catoken);
    }

	@Test
    public void testAutoActivate() throws Exception {
    	CryptoToken catoken = createPKCS11Token();
    	doAutoActivate(catoken);
    }

	@Test
    public void testStoreAndLoad() throws Exception {
    	CryptoToken token = createPKCS11Token();
    	doStoreAndLoad(token);
	}

	@Test
    public void testGenerateSymKey() throws Exception {
    	CryptoToken token = createPKCS11Token();
    	doGenerateSymKey(token);
	}

    @Test
    public void testPKCS11TokenCreation() throws Exception {
        PKCS11CryptoToken token1 = (PKCS11CryptoToken) createPKCS11Token();
        PKCS11CryptoToken token2 = (PKCS11CryptoToken) createPKCS11Token();
        Assert.assertSame("Same token was expected!", token1.getP11slot(), token2.getP11slot());

        PKCS11CryptoToken token3 = (PKCS11CryptoToken) createPKCS11Token("token3", true);
        PKCS11CryptoToken token4 = (PKCS11CryptoToken) createPKCS11Token("token4", true);
        Assert.assertNotSame("Differen token was expected!", token3.getP11slot(), token4.getP11slot());

        PKCS11CryptoToken token5 = (PKCS11CryptoToken) createPKCS11Token("token5", false);
        Assert.assertNotSame("Differen token was expected!", token3.getP11slot(), token5.getP11slot());
    }
    
    @SuppressWarnings("deprecation") //This test will be removed when the deprecated methods it tests are.
    @Test
    public void testUpgradePropertiesFileFrom5_0_x() {
        Properties slotNumberProperties = new Properties();
        slotNumberProperties.setProperty("slot", "7");
        Properties indexProperties = new Properties();
        indexProperties.setProperty("slotListIndex", "7");
        Properties newSlotNumber = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(slotNumberProperties);
        assertEquals("7", newSlotNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE));
        assertEquals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey(), newSlotNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        Properties newIndexNumber = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(indexProperties);
        assertEquals("i7", newIndexNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE));
        assertEquals(Pkcs11SlotLabelType.SLOT_INDEX.getKey(), newIndexNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        
    }
    
    @SuppressWarnings("deprecation")
    @Test
    public void testUpgradePropertiesFileFrom5_0_11() {
        Properties slotPropertiesWithNumber = new Properties();
        slotPropertiesWithNumber.setProperty("slot", "SLOT_ID:7");
        Properties newSlotPropertiesWithNumber = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(slotPropertiesWithNumber);
        assertEquals("7", newSlotPropertiesWithNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE));
        assertEquals(Pkcs11SlotLabelType.SLOT_NUMBER.getKey(), newSlotPropertiesWithNumber.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        Properties slotPropertiesWithIndex = new Properties();
        slotPropertiesWithIndex.setProperty("slot", "SLOT_LIST_IX:i7");
        Properties newSlotPropertiesWithIndex = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(slotPropertiesWithIndex);
        assertEquals("i7", newSlotPropertiesWithIndex.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE));
        assertEquals(Pkcs11SlotLabelType.SLOT_INDEX.getKey(), newSlotPropertiesWithIndex.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
        Properties slotPropertiesWithLabel = new Properties();
        slotPropertiesWithLabel.setProperty("slot", "TOKEN_LABEL:foo");
        Properties newSlotPropertiesWithLabel = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(slotPropertiesWithLabel);
        assertEquals("foo", newSlotPropertiesWithLabel.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE));
        assertEquals(Pkcs11SlotLabelType.SLOT_LABEL.getKey(), newSlotPropertiesWithLabel.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE));
    }

	@Override
	String getProvider() {
		return PKCS11TestUtils.getHSMProvider();
	}

	public static CryptoToken createPKCS11Token() throws NoSuchSlotException {
		return createPKCS11TokenWithAttributesFile(null, null, true);
	}

    public static CryptoToken createPKCS11Token(String name, boolean extractable) throws NoSuchSlotException{
        return createPKCS11TokenWithAttributesFile(null, name, extractable);
    }

	public static CryptoToken createPKCS11TokenWithAttributesFile(String file, String tokenName, boolean extractable) throws NoSuchSlotException {
		Properties prop = new Properties();
        String hsmlib = PKCS11TestUtils.getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, PKCS11TestUtils.getPkcs11SlotValue("1"));
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, PKCS11TestUtils.getPkcs11SlotType(Pkcs11SlotLabelType.SLOT_NUMBER.getKey()).getKey());
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
