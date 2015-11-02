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
package org.cesecore.authorization.user.matchvalues;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * Unit tests for the AccessMatchValueReverseLookupRegistry class.
 * 
 * @version $Id$
 *
 */
public class AccessMatchValueReverseLookupRegistryTest {

    @Test
    public void testVanillaMatchValue() throws SecurityException, NoSuchMethodException {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.register(VanillaAccessMatchValueMock.values());
        } catch (InvalidMatchValueException e) {
            fail("Exception was caught for vanilla AccessMatchValue, test can't proceed");
        }
        //Test that you can't add twice.
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.register(VanillaAccessMatchValueMock.values());
            fail("Added the same lookup method twice"); // NOPMD
        } catch (InvalidMatchValueException e) {
            //Ignore
        }
        VanillaAccessMatchValueMock foo = (VanillaAccessMatchValueMock) AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(VanillaAccessMatchValueMock.TOKEN_TYPE, 0);
        assertEquals("Retrieved match value was not as expected", VanillaAccessMatchValueMock.FOO, foo);
    }

    /**
     * Tests that the lookup registry gives a nice reply to an unregistered token type
     */
    @Test
    public void testLookupUnregisteredTokenType() {
        try {
            AccessMatchValue result = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup("MickeyMouse", 0);
            assertNull("Reverse lookup of an unregistered token type should have returned null", result);
        } catch(NullPointerException e) {
            fail("Lookup for an unregistered token threw an NPE.");
        }
    }

    private enum VanillaAccessMatchValueMock implements AccessMatchValue {
        FOO;
        public static final String TOKEN_TYPE = "foo";
        @Override
        public int getNumericValue() {
            return 0;
        }
        @Override
        public String getTokenType() {
            return TOKEN_TYPE;
        }
        @SuppressWarnings("unused")
        public static AccessMatchValue lookup(Integer value) {
            return FOO;
        }
        @Override
        public boolean isIssuedByCa() {
            return false;
        }
        @Override
        public boolean isDefaultValue() {
            return true;
        }
    }
}
