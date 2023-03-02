/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys.token.pkcs11;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import java.security.Provider;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.pkcs11.PKCS11TestUtils;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabel;
import com.keyfactor.util.keys.token.pkcs11.Pkcs11SlotLabelType;

/**
 * Some general test methods for Pkcs11SlotLabel
 * <p>
 * Requires the following properties to be set in systemtests.proeprties:
 * <ul>
 * <li>pkcs11.library
 * <li>pkcs11.token_number
 * <li>pkcs11.token_label
 * <li>pkcs11.token_index
 * <p>
 * Since pkcs11.token_number might not be a deterministic number, that test may or may not be possible to run in all configurations.
 *
 *
 */
public class Pkcs11SlotLabelTest {

    private static final Logger log = Logger.getLogger(Pkcs11SlotLabelTest.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void checkPkcs11DriverAvailable() {
        // Skip test if no PKCS11 driver is installed
        assumeTrue("No PKCS#11 library configured", PKCS11TestUtils.getHSMLibrary() != null);
    }

    @Test
    public void testgetProviderWithNumber() throws NoSuchSlotException {
        final String number = PKCS11TestUtils.getPkcs11TokenNumber();
        assumeTrue("pkcs11.token_number must be set in systemtests.properties", number != null);
        Provider provider = Pkcs11SlotLabel.getP11Provider(number, Pkcs11SlotLabelType.SLOT_NUMBER, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot number : " + number + " was found.", provider);
    }

    @Test
    public void testgetProviderWithIndex() throws NoSuchSlotException {
        final String index = PKCS11TestUtils.getPkcs11TokenIndex();
        assumeTrue("pkcs11.token_index must be set in systemtests.properties", index != null);
        Provider provider = Pkcs11SlotLabel.getP11Provider(index, Pkcs11SlotLabelType.SLOT_INDEX, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot index : " + index + " was found.", provider);
    }

    @Test
    public void testgetProviderWithLabel() throws NoSuchSlotException {
        final String label = PKCS11TestUtils.getPkcs11TokenLabel();
        assumeTrue("pkcs11.token_label must be set in systemtests.properties", label != null);
        Provider provider = Pkcs11SlotLabel.getP11Provider(label, Pkcs11SlotLabelType.SLOT_LABEL, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot label : " + label + " was found.", provider);
    }
    
    /** 
     * Creates a PKCS#11 Provider using the configured token type and value in systemtests.properties
     * (pkcs11.slottype and pkcs11.slottypevalue).
     * <p>
     * This test is just a safety net, to have one test running even if pkcs11.token_* isn't configured.
     */
    @Test
    public void testgetProviderWithTestDefault() throws NoSuchSlotException {
        final Pkcs11SlotLabelType tokenReferenceType = PKCS11TestUtils.getPkcs11SlotType();
        final String tokenReferenceValue = PKCS11TestUtils.getPkcs11SlotValue();
        log.info("Testing using token type '" + tokenReferenceType + "' and value '" + tokenReferenceValue + "'");
        Provider provider = Pkcs11SlotLabel.getP11Provider(tokenReferenceValue, tokenReferenceType, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for " + tokenReferenceType + " : " + tokenReferenceValue + " was found.", provider);
    }

}
