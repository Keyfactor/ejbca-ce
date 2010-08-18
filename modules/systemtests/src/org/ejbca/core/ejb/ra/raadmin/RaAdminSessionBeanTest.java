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

package org.ejbca.core.ejb.ra.raadmin;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the global configuration entity bean.
 * 
 * TODO: Remake this test into a mocked unit test, to allow testing of a multiple instance database.
 * 
 * @version $Id: GlobalConfigurationTest.java 9657 2010-08-17 11:17:20Z
 *          mikekushner $
 */
public class RaAdminSessionBeanTest extends TestCase {
    private static Logger log = Logger.getLogger(RaAdminSessionBeanTest.class);

    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();

    private Admin administrator;
    private GlobalConfiguration original = null;

    /**
     * Creates a new TestGlobalConfiguration object.
     * 
     * @param name
     *            name
     */
    public RaAdminSessionBeanTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        administrator = new Admin(Admin.TYPE_INTERNALUSER);

        // First save the original
        // FIXME: Do this in @BeforeClass in JUnit4
        if (original == null) {
            original = this.raAdminSession.getCachedGlobalConfiguration(administrator);
        }
    }

    public void tearDown() throws Exception {
        raAdminSession.saveGlobalConfiguration(administrator, original);
        raAdminSession.flushCache();
        administrator = null;
    }

    /**
     * Tests adding a global configuration and waiting for the cache to be updated.
     * 
     * @throws Exception
     *             error
     */
    public void testAddAndReadGlobalConfigurationCache() throws Exception {

        // Read a value to reset the timer
        raAdminSession.getCachedGlobalConfiguration(administrator);
        setInitialValue();
        
        // Set a brand new value
        GlobalConfiguration newValue = new GlobalConfiguration();
        newValue.setEjbcaTitle("BAR");
        raAdminSession.saveGlobalConfiguration(administrator, newValue);

        GlobalConfiguration cachedValue = raAdminSession.getCachedGlobalConfiguration(administrator);

        cachedValue = raAdminSession.getCachedGlobalConfiguration(administrator);
        assertEquals("The GlobalConfigfuration cache was not automatically updated.", "BAR", cachedValue.getEjbcaTitle());

    }
  
    /**
     * Set a preliminary value and allows the cache to set it.
     * @throws InterruptedException
     */
    private void setInitialValue() throws InterruptedException {
        
        GlobalConfiguration initial = new GlobalConfiguration();
        initial.setEjbcaTitle("FOO");
        raAdminSession.saveGlobalConfiguration(administrator, initial);
    }

}
