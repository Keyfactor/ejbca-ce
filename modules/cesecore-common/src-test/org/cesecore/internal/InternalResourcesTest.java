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

import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.util.Properties;

import org.cesecore.config.ConfigurationHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class InternalResourcesTest {

    /** Note diff between EJBCA and CESeCore */
    private static final String TEST_RESOURCE_LOCATION = "/intresources";
    // Classpath issues, use "src/intresources" when running from within eclipse
    //private static final String TEST_RESOURCE_LOCATION = "src/intresources";
	
    @Before
    public void before() {
        ConfigurationHolder.backupConfiguration();
        ConfigurationHolder.updateConfiguration("intresources.secondarylanguage", "sv");
    }
    @After
    public void after() {
        ConfigurationHolder.restoreConfiguration();     
    }
    
    @Test
    public void testGetLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testmsg");
        assertEquals("Test en-US                        ", res);
        assertEquals("Test en-US                        ", intres.getLocalizedMessageCs("raadmin.testmsg").toString());
        // This message will only exist in the secondary language file
        res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test sv-SE", res);
        assertEquals("Test sv-SE", intres.getLocalizedMessageCs("raadmin.testmsgsv").toString());
    }

    @Test
    public void testGetUnfoundMessageButPreserveParameters() {
        InternalResources intres = new InternalResources();
        String result = intres.getLocalizedMessage("foo", "a", "b");
        assertEquals("foo, a, b", result);
    }
    
    @Test
    public void testNonExistingLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.foo");
        assertEquals("raadmin.foo", res);
        assertEquals("raadmin.foo", intres.getLocalizedMessageCs("raadmin.foo").toString());
    }

    @Test
    public void testGetLocalizedMessageStringObject() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", Long.valueOf(1), Integer.valueOf(3), "hi", Boolean.TRUE, "bye");
        assertEquals("Test 1 3 hi true bye message 1 ", res);
        assertEquals("Test 1 3 hi true bye message 1 ", intres.getLocalizedMessageCs("raadmin.testparams", Long.valueOf(1), Integer.valueOf(3), "hi", Boolean.TRUE, "bye").toString());
    }

    @Test
    public void testGetLocalizedMessageStringObjectWithNull() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", null, Integer.valueOf(3), null, Boolean.TRUE, "bye");
        assertEquals("Test  3  true bye message  ", res);
        assertEquals("Test  3  true bye message  ", intres.getLocalizedMessageCs("raadmin.testparams", null, Integer.valueOf(3), null, Boolean.TRUE, "bye").toString());

        res = intres.getLocalizedMessage("raadmin.testparams");
        assertEquals("Test      message  ", res);
        assertEquals("Test      message  ", intres.getLocalizedMessageCs("raadmin.testparams").toString());
    }

    /**
     * Tests the effects of adding extra parameters onto a resource, i.e where the messages says "I am a {0}" and the parameters are "beaver" and 
     * "badger", the resulting output is "I am a beaver, badger", taking care to not lose any information from the output. 
     * 
     */
    @Test
    public void testMessageStringWithExtraParameter() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        Field primaryResource = InternalResources.class.getDeclaredField("primaryResource");
        primaryResource.setAccessible(true);
        Properties intresource = new Properties();
        final String testMessage = "test";
        final String testMessageParams = testMessage + " {0}";
        final String testMessageKey = "test.message";
        final String param = "foo";
        final String extraParam = "bar";
        intresource.setProperty(testMessageKey, testMessageParams);
        primaryResource.set(intres, intresource);
        assertEquals("Extra params were not correctly handled.", testMessage + " " + param + ", " + extraParam, intres.getLocalizedMessage(testMessageKey, param, extraParam).toString());
    }

    /** Test that we don't allow unlimited recursion in the language strings. Recursion will occur when the message is "foo {0}" and the parameter is 
     * "bar {0}". The resulting output will be "foo bar bar bar bar ...", limited by the hard coded limit, which is 20. 
     */
    @Test
    public void testMessageStringWithRecursive() throws NoSuchFieldException, SecurityException {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        Field primaryResource = InternalResources.class.getDeclaredField("primaryResource");
        primaryResource.setAccessible(true);
        Properties intresource = new Properties();
        final String testMessage = "test";
        final String testMessageParams = testMessage + " {0}";
        final String testMessageKey = "test.message";
        final String param0 = "recurse {0}";
        final String param1 = Integer.valueOf(3).toString();
        final String param2 = "bar";
        final String param3 = Boolean.TRUE.toString();
        final String param4 = "bye";
        intresource.setProperty(testMessageKey, testMessageParams);
        String res = intres.getLocalizedMessage(testMessageParams, param0 , param1, param2, param3, param4);
        assertEquals(testMessage + " recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse recurse " + param0 + ", " + param1 + ", "
                + param2 + ", " + param3 + ", " + param4, res);
    }

}
