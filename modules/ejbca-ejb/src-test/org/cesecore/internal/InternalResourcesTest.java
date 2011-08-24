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
package org.cesecore.internal;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Based on EJBCA version: 
 *      InternalResourcesTest.java 8865 2010-04-09 15:14:51Z mikekushner
 * Based on cesecore version:
 *      InternalResourcesTest.java 985 2011-08-10 13:19:09Z tomas
 * 
 * @version $Id$
 */
public class InternalResourcesTest {

	private static final String TEST_RESOURCE_LOCATION = "/intresources";
	// Classpath issues, use "src/intresources" when running from within eclipse
	//private static final String TEST_RESOURCE_PATH = "src/intresources";
	
    @Test
    public void testGetLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testmsg");
        assertEquals("Test ENG", res);
        // This message will only exist in the secondary language file
        res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
    }

    @Test
    public void testNonExistingLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.foo");
        assertEquals("raadmin.foo", res);
    }

    @Test
    public void testGetLocalizedMessageStringObject() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", new Long(1), Integer.valueOf(3), "hi", new Boolean(true), "bye");
        assertEquals("Test 1 3 hi true bye message 1", res);
    }

    @Test
    public void testGetLocalizedMessageStringObjectWithNull() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", null, Integer.valueOf(3), null, new Boolean(true), "bye");
        assertEquals("Test  3  true bye message ", res);

        res = intres.getLocalizedMessage("raadmin.testparams");
        assertEquals("Test      message ", res);
    }

    @Test
    public void testMessageStringWithExtraParameter() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
        res = intres.getLocalizedMessage("raadmin.testmsgsv", "foo $bar \\haaaar");
        assertEquals("Test SV", res);

    }

}
