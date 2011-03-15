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

import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the global configuration entity bean.
 * 
 * TODO: Remake this test into a mocked unit test, to allow testing of a multiple instance database.
 * 
 * @version $Id$
 */
public class GlobalConfigurationSessionBeanTest extends CaTestCase {

	private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();

    private Admin administrator;
    private GlobalConfiguration original = null;

    /**
     * Creates a new TestGlobalConfiguration object.
     * 
     * @param name
     *            name
     */
    public GlobalConfigurationSessionBeanTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        createTestCA();
    	administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);

        // First save the original
        // FIXME: Do this in @BeforeClass in JUnit4
        if (original == null) {
            original = this.globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        }
    }

    public void tearDown() throws Exception {
    	globalConfigurationSession.saveGlobalConfiguration(administrator, original);
    	globalConfigurationSession.flushCache();
        administrator = null;
        removeTestCA();
    }

    /**
     * Tests adding a global configuration and waiting for the cache to be updated.
     * 
     * @throws Exception
     *             error
     */
    public void testAddAndReadGlobalConfigurationCache() throws Exception {

        // Read a value to reset the timer
    	globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        setInitialValue();
        
        // Set a brand new value
        GlobalConfiguration newValue = new GlobalConfiguration();
        newValue.setEjbcaTitle("BAR");
        globalConfigurationSession.saveGlobalConfiguration(administrator, newValue);

        GlobalConfiguration cachedValue = globalConfigurationSession.getCachedGlobalConfiguration(administrator);

        cachedValue = globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        assertEquals("The GlobalConfigfuration cache was not automatically updated.", "BAR", cachedValue.getEjbcaTitle());

    }

	/**
     * Set a preliminary value and allows the cache to set it.
     * @throws InterruptedException
     */
    private void setInitialValue() throws InterruptedException, AuthorizationDeniedException {
        
        GlobalConfiguration initial = new GlobalConfiguration();
        initial.setEjbcaTitle("FOO");
        globalConfigurationSession.saveGlobalConfiguration(administrator, initial);
    }

}
