/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11;

import static org.junit.Assert.assertNotNull;

import java.security.Provider;

import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Some general test methods for Pkcs11SlotLabel
 *
 * 
 * @version $Id$
 *
 */
public class Pkcs11SlotLabelTest {

    private static final String SLOT_NUMBER = "1";
    private static final String SLOT_INDEX = "i1";
    private static final String SLOT_LABEL = "ejbca";

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testgetProviderWithNumber() throws NoSuchSlotException {
        String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        if (pkcs11Library == null) {
            throw new RuntimeException("No known PKCS11 installed, test can't continue.");
        }
        Provider provider = Pkcs11SlotLabel.getP11Provider(SLOT_NUMBER, Pkcs11SlotLabelType.SLOT_NUMBER, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot number : " + SLOT_NUMBER + " was found.", provider);
    }
    
    @Test
    public void testgetProviderWithIndex() throws NoSuchSlotException {
        String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        if (pkcs11Library == null) {
            throw new RuntimeException("No known PKCS11 installed, test can't continue.");
        }
        Provider provider = Pkcs11SlotLabel.getP11Provider(SLOT_INDEX, Pkcs11SlotLabelType.SLOT_INDEX, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot index : " + SLOT_INDEX + " was found.", provider);
    }
    
    @Test
    public void testgetProviderWithLabel() throws NoSuchSlotException {
        String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        if (pkcs11Library == null) {
            throw new RuntimeException("No known PKCS11 installed, test can't continue.");
        }
        Provider provider = Pkcs11SlotLabel.getP11Provider(SLOT_LABEL, Pkcs11SlotLabelType.SLOT_LABEL, PKCS11TestUtils.getHSMLibrary(), null);
        assertNotNull("No provider for slot label : " + SLOT_LABEL + " was found.", provider);
    }
    
}
