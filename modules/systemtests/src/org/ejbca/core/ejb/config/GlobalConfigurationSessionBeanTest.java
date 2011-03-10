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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.authorization.AdminEntitySessionRemote;
import org.cesecore.core.ejb.authorization.AdminGroupSessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the global configuration entity bean.
 * 
 * TODO: Remake this test into a mocked unit test, to allow testing of a multiple instance database.
 * 
 * @version $Id$
 */
public class GlobalConfigurationSessionBeanTest extends CaTestCase {

	private static final Logger LOG = Logger.getLogger(GlobalConfigurationSessionBeanTest.class);
	
    private static final String NONSYSTEMCONFIG_ADMIN = "CN=Admin_Without_Edit_SystemConfig_Right";
    private static final String NONSYSTEMCONFIG_ADMINGROUP = "Non_system_config_Admin_Group";
    
	private GlobalConfigurationSessionRemote globalConfigurationSession = InterfaceCache.getGlobalConfigurationSession();
    private AdminGroupSessionRemote adminGroupSession = InterfaceCache.getAdminGroupSession();
    private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private AdminEntitySessionRemote adminEntitySession = InterfaceCache.getAdminEntitySession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();

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
    
    public void testSaveGlobalConfigurationAuth() throws Exception {
    	try {
    	
    		final GlobalConfiguration globalConfig = globalConfigurationSession.getCachedGlobalConfiguration(administrator);
    	
    		// First test that we can save with an privileged user
    		try {
    			globalConfigurationSession.saveGlobalConfiguration(administrator, globalConfig);
    		} catch (Exception ex) {
    			LOG.error("Error in test", ex);
    			fail("Could not store configuration:" + ex.getMessage());
    		}
    		
    		Admin nonSystemConfigAdmin = setupAdminWithoutEditSystemConfigRights();
    		
    		// Now the real test: make sure we don't have access without edit_systemconfiguration privilege
    		try {
    			globalConfigurationSession.saveGlobalConfiguration(nonSystemConfigAdmin, globalConfig);
    			fail("Authorization should have been denied!");
    		} catch (Exception ignored) {}
    		
    	} finally {
    		adminGroupSession.removeAdminGroup(administrator, NONSYSTEMCONFIG_ADMINGROUP);
    		removeTestCA();
    	}
    }
  
    private Admin setupAdminWithoutEditSystemConfigRights() throws Exception {
    	int caid = getTestCAId(getTestCAName());
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        // Initialize with a new CA
        adminGroupSession.init(admin, caid, NONSYSTEMCONFIG_ADMIN);

        adminGroupSession.addAdminGroup(admin, NONSYSTEMCONFIG_ADMINGROUP);
        
        // Retrieve access rules and check that they were added
        AdminGroup ag = adminGroupSession.getAdminGroup(admin, NONSYSTEMCONFIG_ADMINGROUP);
        assertNotNull("get admingroup", ag);

        // Add some new strange access rules
        ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule("/administrator", AccessRule.RULE_ACCEPT, false));
        adminGroupSession.addAccessRules(admin, NONSYSTEMCONFIG_ADMINGROUP, accessrules);

        // Retrieve the access rules and check that they were added
        ag = adminGroupSession.getAdminGroup(admin, NONSYSTEMCONFIG_ADMINGROUP);
        assertNotNull(ag);
        Collection<AccessRule> rules = ag.getAccessRules();
        assertEquals(1, rules.size()); // We have added one rule
        Iterator<AccessRule> iter = rules.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            AccessRule rule = iter.next();
            if (rule.getAccessRule().equals("/administrator")) {
                found = true;
            }
        }
        assertTrue(found);
        
        // Create end entity
        String adminusername = genRandomUserName();
        Admin intadmin = new Admin(Admin.TYPE_INTERNALUSER);

        UserDataVO userdata = new UserDataVO(adminusername, "CN=" + adminusername, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        userdata.setPassword("foo123");

        userAdminSession.addUser(intadmin, userdata, true);

        File tmpfile = File.createTempFile("ejbca", "p12");
        BatchMakeP12 makep12 = new BatchMakeP12();
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        tmpfile.delete();

        List<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
        adminEntities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, adminusername, caid));
        adminEntitySession.addAdminEntities(intadmin, NONSYSTEMCONFIG_ADMINGROUP, adminEntities);
        authorizationSession.forceRuleUpdate(intadmin);

        X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(intadmin, adminusername).iterator().next();
        admin = new Admin(admincert, adminusername, null);

        assertFalse("Could not setup right authorization rule for test",
                authorizationSession.isAuthorized(admin, "/system_functionality/edit_systemconfiguration"));
        
        return admin;
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
