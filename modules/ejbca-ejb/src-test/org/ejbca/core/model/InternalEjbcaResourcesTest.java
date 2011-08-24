/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model;

import junit.framework.TestCase;

/**
 * @version $Id$
 */
public class InternalEjbcaResourcesTest extends TestCase {

	private static final String TEST_RESOURCE_PATH = "/intresources";
	// Classpath issues, use "src/intresources" when running from within eclipse
	//private static final String TEST_RESOURCE_PATH = "src/intresources";

    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testGetLocalizedMessageString() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("test.testmsg");
        assertEquals("Test ENG", res);
        // This message will only exist in the secondary language file
        res = intres.getLocalizedMessage("test.testmsgsv");
        assertEquals("Test SV", res);
    }

    public void testNonExistingLocalizedMessageString() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("test.foo");
        assertEquals("test.foo", res);
    }

    public void testGetLocalizedMessageStringObject() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("test.testparams", new Long(1), new Integer(3), "hi", new Boolean(true), "bye");
        assertEquals("Test 1 3 hi true bye message 1", res);
    }

    public void testGetLocalizedMessageStringObjectWithNull() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("test.testparams", null, new Integer(3), null, new Boolean(true), "bye");
        assertEquals("Test  3  true bye message ", res);

        res = intres.getLocalizedMessage("test.testparams");
        assertEquals("Test      message ", res);
    }

    public void testMessageStringWithExtraParameter() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("test.testmsgsv");
        assertEquals("Test SV", res);
        res = intres.getLocalizedMessage("test.testmsgsv", "foo $bar \\haaaar");
        assertEquals("Test SV", res);
    }
    
    public void testCeSecoreMessage() {
        InternalEjbcaResources intres = new InternalEjbcaResources(TEST_RESOURCE_PATH);
        String res = intres.getLocalizedMessage("raadmin.testparams", new Long(1), Integer.valueOf(3), "hi", new Boolean(true), "bye");
        assertEquals("Test 1 3 hi true bye message 1", res);    	
    }

}
