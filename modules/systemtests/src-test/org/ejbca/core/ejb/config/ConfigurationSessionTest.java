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

package org.ejbca.core.ejb.config;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests ConfigurationSessionBean
 * 
 * @version $Id$
 */
public class ConfigurationSessionTest {

    private ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    

    @Before
    public void setUp() throws Exception { }
    @After
    public void tearDown() throws Exception { }
    
    @Test
    public void test01BackupRestore() throws Exception {
    	configurationSession.restoreConfiguration();
    	assertFalse("Was able to restore config even though it was never backed up.", configurationSession.restoreConfiguration());
    	assertTrue("Was not able to backup config even though it was never backed up.", configurationSession.backupConfiguration());
    	assertFalse("Was able to backup config even though it was already backed up.", configurationSession.backupConfiguration());
    	assertTrue("Was not able to restore config even though it was backed up.", configurationSession.restoreConfiguration());
    	assertFalse("Was able to restore config even though it was already restored..", configurationSession.restoreConfiguration());
    }

    @Test
    public void test02UpdateValue() throws Exception {
    	final String dummyProperty = "dummy-test-property";
    	configurationSession.restoreConfiguration();
    	assertTrue(dummyProperty + " was already set.", configurationSession.verifyProperty(dummyProperty, null));
    	Properties properties = new Properties();
    	properties.put(dummyProperty, "2");
    	assertTrue("Unable to change configuration.", configurationSession.updateProperties(properties));
    	assertTrue("Was not able to change configuration.", configurationSession.verifyProperty(dummyProperty, "2"));
    	properties.put(dummyProperty, "3");
    	assertTrue("Unable to change configuration.", configurationSession.updateProperties(properties));
    	assertTrue("Was not able to change configuration.", configurationSession.verifyProperty(dummyProperty, "3"));
    	assertTrue("Unable to change configuration.", configurationSession.updateProperty(dummyProperty, "4"));
    	assertTrue("Was not able to change configuration.", configurationSession.verifyProperty(dummyProperty, "4"));
    	assertTrue("Was not able to restore config even though it was backed up.", configurationSession.restoreConfiguration());
    	assertTrue("Reset did not reset test property.", configurationSession.verifyProperty(dummyProperty, null));
    }
}
