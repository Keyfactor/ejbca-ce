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

package org.ejbca.config;

import java.io.File;
import java.io.FileWriter;

import junit.framework.TestCase;

/**
 * Tests the ConfigurationHolder class
 * 
 * @version $Id$
 */
public class ConfigurationHolderTest extends TestCase {
	
	public ConfigurationHolderTest(String name) {
		super(name);
		ConfigurationHolder.instance().clear();
	}

	public void test01GetString() throws Exception {
		File f = File.createTempFile("cesecore", "test");
		try {
			FileWriter fw = new FileWriter(f);
			
			// First the value "property1" should not exists in configuration
			// Test null default value and a default value
			String val = ConfigurationHolder.getString("property1", null);
			assertNull(val);
			val = ConfigurationHolder.getString("property1", "default");
			assertEquals("default", val);
			// Create a configuration file
			fw.write("property1=foo\n");
			fw.write("property2=${property1}bar\n");
			fw.close();
			// We haven't read it so it should still not contain our property
			val = ConfigurationHolder.getString("property1", "default");
			assertEquals("default", val);
			// Add the config file to configuration, now the property should be visible
			ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
			val = ConfigurationHolder.getString("property1", "default");
			assertEquals("foo", val);
			// An expanded string "${property1}bar" will be expanded with the value from "property1" (foo)
			val = ConfigurationHolder.getString("property2", "default");			
			assertEquals("foobar", val);
		} finally {
			f.deleteOnExit();
		}
	}
	
}
