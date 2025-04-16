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

package org.cesecore.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileWriter;

import org.junit.Before;
import org.junit.Test;

/**
 * Tests the ConfigurationHolder class
 * 
 */
public class ConfigurationHolderUnitTest {

    @Before
    public void setUp() {
        ConfigurationHolder.instance().clear();
    }

    @Test
    public void testGetString() throws Exception {
        File f = File.createTempFile("cesecore", "test");
        try {
            // First the value "property1" should not exists in configuration
            // Test null default value and a default value
            assertNull("non-existing property should be null by default", ConfigurationHolder.getString("property1"));
            try (FileWriter fw = new FileWriter(f)) {
                // Create a configuration file
                fw.write("property1=foo\n");
                fw.write("property2=${property1}bar\n");
                // Make sure we handle comma in values
                fw.write("property3=EN,DE,FR\n");
            }
            // We haven't read it so it should still not contain our property
            String val = ConfigurationHolder.getString("property1");
            assertEquals(null, val);
            // Add the config file to configuration, now the property should be visible
            ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
            val = ConfigurationHolder.getString("property1");
            assertEquals("foo", val);
            // An expanded string "${property1}bar" will be expanded with the value from "property1" (foo)
            val = ConfigurationHolder.getString("property2");
            assertEquals("foobar", val);
            // Make sure we handle comma in values
            val = ConfigurationHolder.getString("property3");
            assertEquals("EN,DE,FR", val);
        } finally {
            f.deleteOnExit();
        }
    }

}
