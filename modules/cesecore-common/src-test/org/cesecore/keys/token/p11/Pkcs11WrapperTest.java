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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11SlotListWrapper;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests instantiating the PKCS11SlotListWrapper
 */
public class Pkcs11WrapperTest {

    private static final Logger log = Logger.getLogger(Pkcs11WrapperTest.class);

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
    public void testInstantiatePkcs11Wrapper() {
        String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        try {
            Pkcs11SlotLabel.getSlotListWrapper(new File(pkcs11Library));
        } catch (Exception e) {
            log.error("Unknown exception encountered", e);
            fail("Exception was thrown, instantiation failed.");
        }
    }
    
    private PKCS11SlotListWrapper getPkcs11Wrapper() {
        final String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        return Pkcs11SlotLabel.getSlotListWrapper(new File(pkcs11Library));
    }

    /**
     * Verifies that the getTokenLabel method works. Note that this method will fail in HSMs without
     * fixed slot numbers, e.g. nCypher
     * <p>
     * Requires that pkcs11.token_number and pkcs11.token_label properties to be set in systemtests.properties
     */
    @Test
    public void testGetTokenLabel() {
        assumeTrue("pkcs11.token_number and pkcs11.token_label must be set for this test to work",
                PKCS11TestUtils.getPkcs11TokenNumber() != null && PKCS11TestUtils.getPkcs11TokenLabel() != null);
        final PKCS11SlotListWrapper pkcs11Wrapper = getPkcs11Wrapper();
        final long tokenId = Long.valueOf(PKCS11TestUtils.getPkcs11TokenNumber());
        final char[] foundLabel = pkcs11Wrapper.getTokenLabel(tokenId);
        assertNotNull("Label was not found", foundLabel);
        assertEquals("Wrong token label was returned.", PKCS11TestUtils.getPkcs11TokenLabel(), new String(foundLabel));
    }

    /**
     * Tests the getSlotList method. Depending on the PKCS#11 configuration, it will test different things:
     * <ul>
     * <li>For SLOT_INDEX, we check that the index is present in the list.
     * <li>For SLOT_NUMBER, we check that the number (token ID) is present in the list.
     * <li>For SLOT_LABEL, we check that there is a slot/token with the configured label.
     */
    @Test
    public void testGetSlotList() {
        final PKCS11SlotListWrapper pkcs11Wrapper = getPkcs11Wrapper();
        final long[] tokenIds = pkcs11Wrapper.getSlotList();
        assertTrue("Should have at least one slot/token.", tokenIds.length > 0);
        final Pkcs11SlotLabelType tokenReferenceType = PKCS11TestUtils.getPkcs11SlotType();
        log.info("Testing " + tokenReferenceType);
        switch (tokenReferenceType) {
        case SLOT_INDEX:
            assertTrue("Configured slot/token index was not found.", tokenIds.length >= Integer.valueOf(StringUtils.removeStart(PKCS11TestUtils.getPkcs11SlotValue(), "i")));
            break;
        case SLOT_LABEL:
            final String expectedLabel = PKCS11TestUtils.getPkcs11SlotValue();
            assertTrue("Configured slot/token label was not found.", Arrays.stream(tokenIds).anyMatch(
                    tokenId -> expectedLabel.equals(String.valueOf(pkcs11Wrapper.getTokenLabel(tokenId)))));
            break;
        case SLOT_NUMBER:
            final long expectedId = Long.valueOf(PKCS11TestUtils.getPkcs11SlotValue());
            assertTrue("Configured slot/token label was not found.", ArrayUtils.contains(tokenIds, expectedId));
            break;
        case SUN_FILE:
            assumeTrue("Cannot test slot/token type " + PKCS11TestUtils.getPkcs11SlotType(), false);
        }
    }
    
    /**
     * Tests the getSlotList method and getSlotLabel methods together. Works regardless of PKCS#11 slot/token configuration,
     * but cannot check the results. 
     */
    @Test
    public void testGetSlotListLabels() {
        PKCS11SlotListWrapper pkcs11Wrapper = getPkcs11Wrapper();
        long[] tokenIds = pkcs11Wrapper.getSlotList();
        assertTrue("Should have at least one slot/token.", tokenIds.length > 0);
        for (final long tokenId : tokenIds) {
            pkcs11Wrapper.getTokenLabel(tokenId);
        }
    }

}
