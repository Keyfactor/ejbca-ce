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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;

import org.apache.commons.configuration2.CompositeConfiguration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.configuration2.convert.LegacyListDelimiterHandler;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests the ConfigurationHolder class
 * 
 * @version $Id$
 */
public class ConfigurationHolderTest {

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

    @Test
    public void testGetDefaultValuesWithCommas() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException, IOException, ConfigurationException {        
        // Make sure we handle comma in default values
        String val = ConfigurationHolder.getString("intresources.preferredlanguage");
        assertEquals("en", val);
        // A little reflection magic just to avoid dumping a test value in defaultvalues.properties file.
        Field field = ConfigurationHolder.class.getDeclaredField("defaultValues");
        field.setAccessible(true);
        CompositeConfiguration defaultValues = (CompositeConfiguration) field.get(null);
        val = ConfigurationHolder.getString("test.comma.in.defaultvalue");
        assertNull(val);
        File f = File.createTempFile("cesecore", "test");
        try {
            try (FileWriter fw = new FileWriter(f)) {
                fw.write("test.comma.in.defaultvalue=EN,DE,FR\n");
            }
            defaultValues.addConfiguration(loadProperties(f));
            val = ConfigurationHolder.getString("test.comma.in.defaultvalue");
            assertEquals("EN,DE,FR", val);
        } finally {
            f.deleteOnExit();
        }
    }
    
    private static PropertiesConfiguration loadProperties(final File file) throws ConfigurationException {
        final FileBasedConfigurationBuilder<PropertiesConfiguration> builder =
                new FileBasedConfigurationBuilder<PropertiesConfiguration>(PropertiesConfiguration.class)
                .configure(new Parameters().properties()
                    .setFile(file)
                    .setThrowExceptionOnMissing(false)
                    .setListDelimiterHandler(new LegacyListDelimiterHandler(';'))
                    .setIncludesAllowed(false));
        final PropertiesConfiguration config = builder.getConfiguration();
        return config;
    }
}
