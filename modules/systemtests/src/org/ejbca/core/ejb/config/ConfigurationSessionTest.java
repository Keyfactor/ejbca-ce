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

package org.ejbca.core.ejb.config;

import java.util.Properties;
import junit.framework.TestCase;
import org.ejbca.util.TestTools;

/**
 * Tests ConfigurationSessionBean
 * 
 * @version $Id$
 */
public class ConfigurationSessionTest extends TestCase {

	public ConfigurationSessionTest(String name) {
        super(name);
	}
	
    public void setUp() throws Exception { }
    public void tearDown() throws Exception { }
    
    /**
     * Test that back and restore works as expected.
     */
    public void test01BackupRestore() throws Exception {
    	TestTools.getConfigurationSession().restoreConfiguration();
    	assertFalse("Was able to restore config even though it was never backed up.", TestTools.getConfigurationSession().restoreConfiguration());
    	assertTrue("Was not able to backup config even though it was never backed up.", TestTools.getConfigurationSession().backupConfiguration());
    	assertFalse("Was able to backup config even though it was already backed up.", TestTools.getConfigurationSession().backupConfiguration());
    	assertTrue("Was not able to restore config even though it was backed up.", TestTools.getConfigurationSession().restoreConfiguration());
    	assertFalse("Was able to restore config even though it was already restored..", TestTools.getConfigurationSession().restoreConfiguration());
    }

    /**
     * Test that updating properties works
     */
    public void test02UpdateValue() throws Exception {
    	final String dummyProperty = "dummy-test-property";
    	TestTools.getConfigurationSession().restoreConfiguration();
    	assertTrue(dummyProperty + " was already set.", TestTools.getConfigurationSession().verifyProperty(dummyProperty, null));
    	Properties properties = new Properties();
    	properties.put(dummyProperty, "2");
    	assertTrue("Unable to change configuration.", TestTools.getConfigurationSession().updateProperties(properties));
    	assertTrue("Was not able to change configuration.", TestTools.getConfigurationSession().verifyProperty(dummyProperty, "2"));
    	properties.put(dummyProperty, "3");
    	assertTrue("Unable to change configuration.", TestTools.getConfigurationSession().updateProperties(properties));
    	assertTrue("Was not able to change configuration.", TestTools.getConfigurationSession().verifyProperty(dummyProperty, "3"));
    	assertTrue("Unable to change configuration.", TestTools.getConfigurationSession().updateProperty(dummyProperty, "4"));
    	assertTrue("Was not able to change configuration.", TestTools.getConfigurationSession().verifyProperty(dummyProperty, "4"));
    	assertTrue("Was not able to restore config even though it was backed up.", TestTools.getConfigurationSession().restoreConfiguration());
    	assertTrue("Reset did not reset test property.", TestTools.getConfigurationSession().verifyProperty(dummyProperty, null));
    }
}
