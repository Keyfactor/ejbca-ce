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

import java.util.Collection;

import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CaSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the global configuration entity bean.
 * 
 * TODO: Remake this test into a mocked unit test, to allow testing of a multiple instance database.
 * TODO: Add more tests for other remote methods similar to testNonCLIUser_* and testDisabledCLI_*.
 * 
 * @version $Id$
 */
public class GlobalConfigurationSessionBeanTest extends CaTestCase {

	private static final Admin[] NON_CLI_ADMINS = new Admin[] {
		new Admin(Admin.TYPE_INTERNALUSER),
		new Admin(Admin.TYPE_PUBLIC_WEB_USER)
	}; 
	
	private Collection<Integer> caids;
	
	private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
	
	private CaSessionRemote caSession = InterfaceCache.getCaSession();
	private CAAdminSessionRemote caAdminSession = InterfaceCache.getCAAdminSession();
	private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();

    private Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);;
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
    	enableCLI(true);
    	createTestCA();    	

        // First save the original
        // FIXME: Do this in @BeforeClass in JUnit4
        if (original == null) {
            original = this.globalConfigurationSession.getCachedGlobalConfiguration(administrator);
        }
    	caids = caSession.getAvailableCAs(administrator);
    	assertFalse("No CAs exists so this test will not work", caids.isEmpty());
    }

    public void tearDown() throws Exception {
    	globalConfigurationSession.saveGlobalConfigurationRemote(administrator, original);
    	enableCLI(true);
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
        globalConfigurationSession.saveGlobalConfigurationRemote(administrator, newValue);

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
        globalConfigurationSession.saveGlobalConfigurationRemote(administrator, initial);
    }
    
    /**
     * Tests that we can not pretend to be something other than command line 
     * user and call the method getAvailableCAs.
     * @throws Exception
     */
    public void testNonCLIUser_getAvailableCAs() throws Exception {
    	enableCLI(true);
    	for (Admin admin : NON_CLI_ADMINS) {
    		operationGetAvailabeCAs(admin);
    	}
    }
    /**
     * Tests that we can disable the CLI and then that we can not call the 
     * method getAvailableCAs.
     * @throws Exception
     */
    public void testDisabledCLI_getAvailableCAs() throws Exception {
    	enableCLI(false);
    	operationGetAvailabeCAs(administrator);
    }
    
    /**
     * Tests that we can not pretend to be something other than command line 
     * user and call the method getAvailableCAs.
     * @throws Exception
     */
    public void testNonCLIUser_getCAInfo() throws Exception {
    	enableCLI(true);
    	for (Admin admin : NON_CLI_ADMINS) {
    		operationGetCAInfo(admin, caids);
    	}
    }
    /**
     * Tests that we can disable the CLI and then that we can not call the 
     * method getAvailableCAs.
     * @throws Exception
     */
    public void testDisabledCLI_getCAInfo() throws Exception {
    	enableCLI(false);
    	operationGetCAInfo(administrator, caids);
    }
    
    /** 
     * Enables/disables CLI and flushes caches unless the property does not
     * aready have the right value.
     * @param enable
     */
    private void enableCLI(final boolean enable) {
    	final GlobalConfiguration config = globalConfigurationSession.flushCache();
    	final GlobalConfiguration newConfig;
    	if (config.getEnableCommandLineInterface() == enable) {
    		newConfig = config;
    	} else {
	    	config.setEnableCommandLineInterface(enable);
	    	globalConfigurationSession.saveGlobalConfigurationRemote(administrator, config);
	    	newConfig = globalConfigurationSession.flushCache();
    	}
    	assertEquals("CLI should have been enabled/disabled",
    			enable, newConfig.getEnableCommandLineInterface());
    	authorizationSession.flushAuthorizationRuleCache();
    }
    
    /**
     * Try to get available CAs. Test assumes the CLI is disabled or that the admin
     *  is not authorized.
     * @param admin To perform the operation with.
     */
    private void operationGetAvailabeCAs(final Admin admin) {
    	// Get some CA ids: should be empty now
    	final Collection<Integer> emptyCaids = caSession.getAvailableCAs(admin);
    	assertTrue("Should not have got any CAs as admin of type "
    			+ admin.getAdminType(), emptyCaids.isEmpty());
    }
    
    /**
     * Try to get CA infos. Test assumes the CLI is disabled or that the admin
     *  is not authorized.
     * @param admin to perform the operation with.
     * @param knownCaids IDs to test with.
     */
    private void operationGetCAInfo(final Admin admin, final Collection<Integer> knownCaids) {
    	// Get CA infos: We should not get any CA infos even if we know the IDs
    	for (int caid : knownCaids)  {
    		final CAInfo ca = caAdminSession.getCAInfo(admin, caid);
    		assertNull("Got CA " + caid + " as admin of type " + admin.getAdminType(), ca);
    	}
    }

}
