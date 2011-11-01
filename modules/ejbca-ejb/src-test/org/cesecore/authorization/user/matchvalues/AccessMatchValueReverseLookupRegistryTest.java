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

import java.security.InvalidParameterException;

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
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(VanillaAccessMatchValueMock.TOKEN_TYPE,
                    VanillaAccessMatchValueMock.class.getMethod("lookup", Integer.class));
        } catch (InvalidMatchValueException e) {
            fail("Exception was caught for vanilla AccessMatchValue, test can't proceed");
        }
        
        //Test that you can't add twice.
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(VanillaAccessMatchValueMock.TOKEN_TYPE,
                    VanillaAccessMatchValueMock.class.getMethod("lookup", Integer.class));
            fail("Added the same lookup method twice");
        } catch (InvalidMatchValueException e) {
            //Ignore
        }
        VanillaAccessMatchValueMock foo = (VanillaAccessMatchValueMock) AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(VanillaAccessMatchValueMock.TOKEN_TYPE, 0);
        assertEquals("Retrieved match value was not as expected", VanillaAccessMatchValueMock.FOO, foo);
        
        //Test the reverse lookup
        
    }

    /**
     * This test checks that the return type is checked.
     * 
     * @throws Exception
     */
    @Test
    public void testInstanceCheck() throws Exception {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(IncorrectInstanceAccessMatchValueMock.TOKEN_TYPE,
                    IncorrectInstanceAccessMatchValueMock.class.getMethod("lookup"));
            fail("Should have caught exception for method with invalid return type.");
        } catch (InvalidMatchValueException e) {
            //Ignore
        }

    }

    /**
     * This test checks that the method must be public
     * 
     * @throws Exception
     */
    @Test
    public void testPublicCheck() throws Exception {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(PrivateAccessMatchValueMock.TOKEN_TYPE,
                    PrivateAccessMatchValueMock.class.getDeclaredMethod("lookup"));
            fail("Should have caught exception with private method.");
        } catch (InvalidMatchValueException e) {
            //Ignore
        }
    }

    /**
     * This test checks that the method must be static
     * 
     * @throws Exception
     */
    @Test
    public void testStaticCheck() throws Exception {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(UnstaticAccessMatchValueMock.TOKEN_TYPE,
                    UnstaticAccessMatchValueMock.class.getMethod("lookup"));
            fail("Should have caught exception private method.");
        } catch (InvalidMatchValueException e) {
            //Ignore
        }
    }

    /**
     * Test that registerLookupMethod performs a null check on the params
     * @throws NoSuchMethodException 
     * @throws SecurityException 
     */
    @Test
    public void testRegisterLookupMethodParameterNullCheck() throws SecurityException, NoSuchMethodException {
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(null, VanillaAccessMatchValueMock.class.getMethod("lookup", Integer.class));
            fail("Should not have been able to set tokenType parameter null");
        } catch (InvalidParameterException e) {
            //Ignore
        }
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
    }

    public enum PrivateAccessMatchValueMock implements AccessMatchValue {
        FOO;
        public static final String TOKEN_TYPE = "xyy";
        @Override
        public int getNumericValue() {
            return 0;
        }
        @Override
        public String getTokenType() {
            return TOKEN_TYPE;
        }
        @SuppressWarnings("unused")
        private static AccessMatchValue lookup() {
            return FOO;
        }
    }

    private enum UnstaticAccessMatchValueMock implements AccessMatchValue {
        FOO;
        public static final String TOKEN_TYPE = "qrr";
        @Override
        public int getNumericValue() {
            return 0;
        }
        @Override
        public String getTokenType() {
            return TOKEN_TYPE;
        }
        @SuppressWarnings("unused")
        public AccessMatchValue lookup() {
            return FOO;
        }
    }

    private enum IncorrectInstanceAccessMatchValueMock implements AccessMatchValue {
        FOO;
        public static final String TOKEN_TYPE = "bar";
        @Override
        public int getNumericValue() {
            return 0;
        }
        @Override
        public String getTokenType() {
            return TOKEN_TYPE;
        }
        @SuppressWarnings("unused")
        public static String lookup() {
            return "foo";
        }
    }

}
