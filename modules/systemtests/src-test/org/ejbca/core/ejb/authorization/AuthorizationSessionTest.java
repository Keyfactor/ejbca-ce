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

package org.ejbca.core.ejb.authorization;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.core.ejb.authorization.AdminEntitySessionRemote;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupDoesNotExistException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.InterfaceCache;

/**
 * Tests authentication session used by signer.
 * 
 * @version $Id$
 */
public class AuthorizationSessionTest extends CaTestCase {

    private static final String DEFAULT_SUPERADMIN_CN = "SuperAdmin";
    private static final String SUPER_ADMIN = "superadmin";
    private static final String TEST_GROUPNAME = "testgroup";

    // private static final Logger log =
    // Logger.getLogger(AuthorizationSessionTest.class);

    private AdminEntitySessionRemote adminEntitySession = InterfaceCache.getAdminEntitySession();
    private AdminGroupSessionRemote adminGroupSession = InterfaceCache.getAdminGroupSession();
    private AuthorizationSessionRemote authorizationSession = InterfaceCache.getAuthorizationSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    /**
     * Creates a new TestAuthenticationSession object.
     * 
     * @param name
     *            name
     */
    public AuthorizationSessionTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        super.setUp();
        createTestCA();
    }

    public void tearDown() throws Exception {
        super.tearDown();
        removeTestCA();
    }

    /**
     * tests initialization of authorization bean
     * 
     * @throws Exception
     *             error
     */
    public void testInitialize() throws Exception {
        int caid = "CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        // Initialize with a new CA
        adminGroupSession.init(admin, caid, DEFAULT_SUPERADMIN_CN);

        // Retrieve access rules and check that they were added
        AdminGroup ag = adminGroupSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        Collection<AccessRule> rules = ag.getAccessRules();
        assertEquals("Number of available access rules for AdminGroup.PUBLICWEBGROUPNAME was not the expected.", 8, rules.size());

        // Add some new strange access rules
        ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule("/public_foo_user", AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule("/foo_functionality/basic_functions", AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule("/foo_functionality/view_certificate", AccessRule.RULE_ACCEPT, false));
        adminGroupSession.addAccessRules(admin, AdminGroup.PUBLICWEBGROUPNAME, accessrules);

        // Retrieve the access rules and check that they were added
        ag = adminGroupSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(11, rules.size()); // We have added three rules
        Iterator<AccessRule> iter = rules.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            AccessRule rule = iter.next();
            if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
                found = true;
            }
        }
        assertTrue(found);

        // Initialize the same CA again, this will remove old default Public Web
        // rules and create new ones.
        // This had some troubles with glassfish before, hence the creation of
        // this test
        adminGroupSession.init(admin, caid, DEFAULT_SUPERADMIN_CN);
        // Retrieve access rules and check that we only have the default ones
        ag = adminGroupSession.getAdminGroup(admin, AdminGroup.PUBLICWEBGROUPNAME);
        assertNotNull(ag);
        rules = ag.getAccessRules();
        assertEquals(8, rules.size());
        iter = rules.iterator();
        found = false;
        while (iter.hasNext()) {
            AccessRule rule = (AccessRule) iter.next();
            if (rule.getAccessRule().equals("/foo_functionality/view_certificate")) {
                found = true;
            }
        }
        assertFalse(found);

    }

    public void testExistMethods() throws Exception {
        int caid = "CN=TEST Authorization,O=PrimeKey,C=SE".hashCode();
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        authorizationSession.existsCAInRules(admin, caid);

    }

    public void testIsAuthorizedInternalUserRegularApproveIdentity() {
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        assertTrue("Could not authorize internal user with AccessRulesConstants.REGULAR_APPROVEENDENTITY",
                authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY));

    }

    public void testIsAuthorizedCertUserRegularApproveIdentity() throws Exception {

        String adminusername = genRandomUserName();
        AuthenticationToken intadmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

        int caid = getTestCAId();

        EndEntityInformation userdata = new EndEntityInformation(adminusername, "CN=" + adminusername, caid, null, null, 1, SecConst.EMPTY_ENDENTITYPROFILE,
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
        adminEntitySession.addAdminEntities(intadmin, AdminGroup.TEMPSUPERADMINGROUP, adminEntities);
        authorizationSession.forceRuleUpdate(intadmin);

        X509Certificate admincert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(adminusername).iterator().next();
        Admin admin = new Admin(admincert, adminusername, null);

        assertTrue("Could not authorize certificate user with AccessRulesConstants.REGULAR_APPROVEENDENTITY",
                authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY));

    }

    /**
     * 
     * This test reproduces an error where the superadmin user was invalid.
     * 
     * @throws AuthorizationDeniedException
     */
    public void testIsAuthorizedWithSuperAdminFromX509Certificate() throws AuthorizationDeniedException {
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        Admin superadmin = new Admin((X509Certificate) certificateStoreSession.findCertificatesByUsername(SUPER_ADMIN).iterator().next(),
                SUPER_ADMIN, null);
        assertTrue("Authorization for superadmin user failed. This probably means that your SuperAdmin user isn't feeling very well.",
                authorizationSession.isAuthorized(superadmin, AccessRulesConstants.REGULAR_APPROVEENDENTITY));

    }

    /**
     * Tests the method isAuthorizedToGroup, happypath.
     * 
     * @throws AdminGroupExistsException
     * @throws AdminGroupDoesNotExistException
     */
    public void testIsAuthorizedToGroup_Authorized() throws AdminGroupExistsException, AdminGroupDoesNotExistException {
        // Set up
        final String testCaName = "FailureTestCA";
        final String testAdminName = "FailureAdmin";

        createTestCA(testCaName);

        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        Admin anAdmin = new Admin(getTestCACert(testCaName), testAdminName, null);

        List<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule(AccessRulesConstants.CAPREFIX + ("CN=" + testCaName).hashCode(), AccessRule.RULE_ACCEPT, false));

        cleanUpAdminGroupTests(anAdmin, TEST_GROUPNAME, accessrules);
        adminGroupSession.addAdminGroup(anAdmin, TEST_GROUPNAME);

        List<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
        adminEntities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, testCaName, ("CN=" + testCaName).hashCode()));
        adminEntitySession.addAdminEntities(anAdmin, TEST_GROUPNAME, adminEntities);

        adminGroupSession.addAccessRules(anAdmin, TEST_GROUPNAME, accessrules);

        authorizationSession.forceRuleUpdate(admin);
        try {
            // Do test with internal user
            assertTrue("Internal user was not authorized to group <" + TEST_GROUPNAME + "> as expected.",
                    authorizationSession.isAuthorizedToGroup(admin, TEST_GROUPNAME));
            // Do test with external user
            assertTrue("Admin of type " + anAdmin + " not authorized to group <" + TEST_GROUPNAME + "> as expected.",
                    authorizationSession.isAuthorizedToGroup(anAdmin, TEST_GROUPNAME));
        } finally {
            // Clean up
            cleanUpAdminGroupTests(anAdmin, TEST_GROUPNAME, accessrules);
            removeTestCA(testCaName);
        }
    }

    /**
     * Cleans up for AdminGroup-related tests
     * 
     * @param admin
     * @param groupname
     * @param accessRules
     */
    private void cleanUpAdminGroupTests(Admin admin, String groupname, List<AccessRule> accessRules) {
        List<String> accessRuleNames = new ArrayList<String>();
        for (AccessRule accessRule : accessRules) {
            accessRuleNames.add(accessRule.getAccessRule());
        }
        if (adminGroupSession.getAdminGroup(admin, groupname) != null) {
            adminGroupSession.removeAccessRules(admin, groupname, accessRuleNames);
            adminGroupSession.removeAdminGroup(admin, groupname);
        }
    }

    /**
     * Tests authorization to a group when it doesn't have any admin entities
     * @throws AdminGroupExistsException 
     */
    public void testIsAuthorizedToGroupWhenEmpty() throws AdminGroupExistsException {
        // Set up
        final String testCaName = "FailureTestCA";
        final String testAdminName = "FailureAdmin";
        createTestCA(testCaName);
        Admin anAdmin = new Admin(getTestCACert(testCaName), testAdminName, null);
        // Do test with external user and an empty group

        List<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule(AccessRulesConstants.CAPREFIX + ("CN=SpiderMonkey").hashCode(), AccessRule.RULE_ACCEPT, false));
        
        cleanUpAdminGroupTests(anAdmin, TEST_GROUPNAME, accessrules);
        adminGroupSession.addAdminGroup(anAdmin, TEST_GROUPNAME);
        
        try {
            assertTrue("Admin of type " + anAdmin + " with username " + anAdmin.getUsername() + " was authorized to group <" + TEST_GROUPNAME
                    + "> incorrectly when group was empty.", authorizationSession.isAuthorizedToGroup(anAdmin, TEST_GROUPNAME));
        } finally {
            // Clean up
            adminGroupSession.removeAdminGroup(anAdmin, TEST_GROUPNAME);
            removeTestCA(testCaName);
        }
    }

    /**
     * This tests failure scenarios for the method isAuthorizedToGroup()
     * 
     * @throws AdminGroupExistsException
     */
    public void testIsAuthorizedToGroup_Failure() throws AdminGroupExistsException {
        // Set up
        final String testCaName = "FailureTestCA";
        final String testAdminName = "FailureAdmin";
        createTestCA(testCaName);

        Admin anAdmin = new Admin(getTestCACert(testCaName), testAdminName, null);

        List<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule(AccessRulesConstants.CAPREFIX + ("CN=SpiderMonkey").hashCode(), AccessRule.RULE_ACCEPT, false));

        cleanUpAdminGroupTests(anAdmin, TEST_GROUPNAME, accessrules);
        adminGroupSession.addAdminGroup(anAdmin, TEST_GROUPNAME);

        try {
            List<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
            adminEntities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, DEFAULT_SUPERADMIN_CN,
                    "CN=TEST Authorization,O=PrimeKey,C=SE".hashCode()));
            
            adminEntitySession.addAdminEntities(anAdmin, TEST_GROUPNAME, adminEntities);

            assertFalse("Admin of type " + anAdmin + " with username " + anAdmin.getUsername() + " was authorized to group <" + TEST_GROUPNAME
                    + "> incorrectly when group was not empty.", authorizationSession.isAuthorizedToGroup(anAdmin, TEST_GROUPNAME));

        } finally {
            // Clean up
            adminGroupSession.removeAdminGroup(anAdmin, TEST_GROUPNAME);
            removeTestCA(testCaName);
        }
    }
    
    public void testExistsEndEntityProfileInRules() {
        Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
        // profile id, random, should not exist in any rules
        Random rand = new Random();
        int id = rand.nextInt(100000);
    	boolean result = authorizationSession.existsEndEntityProfileInRules(admin, id);
    	assertFalse("Id "+id+" exists in access rules, did we generate a real existing id?", result);
    	// Add the id to access rules
        try {
            List<AccessRule> accessrules = new ArrayList<AccessRule>();
            accessrules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEPREFIX + id, AccessRule.RULE_ACCEPT, false));
            cleanUpAdminGroupTests(admin, TEST_GROUPNAME, accessrules);
            try {
				adminGroupSession.addAdminGroup(admin, TEST_GROUPNAME);
			} catch (AdminGroupExistsException e) {
				// NOPMD: do nothing
			}
            adminGroupSession.addAccessRules(admin, TEST_GROUPNAME, accessrules);
            // Try again, not it should exist
        	result = authorizationSession.existsEndEntityProfileInRules(admin, id);
        	assertTrue("Id "+id+" should have existed in an access rule", result);
        } finally {
            // Clean up
            adminGroupSession.removeAdminGroup(admin, TEST_GROUPNAME);
        }

    }
}
