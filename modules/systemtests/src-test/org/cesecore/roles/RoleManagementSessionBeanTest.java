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
package org.cesecore.roles;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleExistsException;
import org.cesecore.authorization.rules.AccessRuleManagementTestSessionRemote;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectExistsException;
import org.cesecore.authorization.user.AccessUserAspectManagerTestSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 * 
 */
public class RoleManagementSessionBeanTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(RoleManagementSessionBeanTest.class);
    
    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private AccessRuleManagementTestSessionRemote accessRuleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessRuleManagementTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private AccessUserAspectManagerTestSessionRemote accessUserAspectManagerSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessUserAspectManagerTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    
    private AuthenticationToken authenticationToken;
    private AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "RoleManagementSessionBeanTest"));
   

    @Before
    public void setUp() throws RoleExistsException, RoleNotFoundException {
    	setUpAuthTokenAndRole("RoleManagementSessionTest");
    	// In this test case we can just use the same auth token as used to initialize the role mgmt
    	authenticationToken = roleMgmgToken;
    }

    @After
    public void tearDown() throws RoleNotFoundException, AuthorizationDeniedException {
    	tearDownRemoveRole();
    }

    /**
     * Basic sanity test.
     * @throws AuthorizationDeniedException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testCrudOperation() throws AuthorizationDeniedException, RoleNotFoundException {

        AdminGroupData role = null;
        final String roleName = "Nibbler";
        AdminGroupData foundRole = null;
        try {
            role = roleManagementSession.create(authenticationToken, roleName);
        } catch (RoleExistsException e) {
            fail("Tried adding a role that already exists. Is the database clean?");
        }

        try {
            boolean caught = false;
            try {
                roleManagementSession.create(authenticationToken, roleName);
            } catch (RoleExistsException e) {
                caught = true;
            }
            assertTrue("RoleExistsException was not tossed when attempting to add an existing role to persistence.", caught);

            // Find a role by a known primary key.
            foundRole = roleAccessSession.findRole(role.getPrimaryKey());
            assertNotNull("RoleData with known primary key could not be retrieved from database.", foundRole);
            assertEquals("Created role and retrieved role with same primary key were not equal.", role, foundRole);

        } finally {
            roleManagementSession.remove(authenticationToken, foundRole);
        }

    }

    /**
     * Further tests aspects of the remove methods.
     * 
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testRemoveByName() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String roleName = "Hermes";

        AdminGroupData role = roleManagementSession.create(authenticationToken, roleName);
        assertNotNull("Initial role was not created, can not proceed with test.",
                roleAccessSession.findRole(role.getPrimaryKey()));

        roleManagementSession.remove(authenticationToken, roleName);
        assertNull("Role by name " + roleName + " was not correctly deleted.",
                roleAccessSession.findRole(role.getPrimaryKey()));

        // Try removing a non existent role. Should deliver a RoleNotFoundException
        try {
            roleManagementSession.remove(authenticationToken, "Fry");
            assertTrue("RoleNotFoundException was not thrown when trying to delete a non-existant role by name.", false);
        } catch (RoleNotFoundException e) {
                // NOPMD
        }
    }

    /**
     * Tests getting multiple roles from database.
     * 
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testGetAllroles() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String firstRoleName = "Bender";
        final String secondRoleName = "Leela";

        Collection<AdminGroupData> roles = roleAccessSession.getAllRoles();
        final int roleSizeBeforeTest = roles.size();

        roleManagementSession.create(authenticationToken, firstRoleName);
        roleManagementSession.create(authenticationToken, secondRoleName);
        try {
            roles = roleAccessSession.getAllRoles();
            assertTrue(roles.size() == (roleSizeBeforeTest+2));
        } finally {
            roleManagementSession.remove(authenticationToken, firstRoleName);
            roleManagementSession.remove(authenticationToken, secondRoleName);
            assertEquals("testGetAllroles did not clean up after itself properly.", roleSizeBeforeTest, roleAccessSession.getAllRoles().size());
        }
    }

    @Test
    public void testAddAndRemoveAccessUsersToRole() throws RoleExistsException, AccessUserAspectExistsException, AuthorizationDeniedException, RoleNotFoundException {
        AdminGroupData role = roleManagementSession.create(authenticationToken, "Zoidberg");
        final int caId = 1337;
        final int benderPrimaryKey = AccessUserAspectData.generatePrimaryKey(role.getRoleName(), caId, X500PrincipalAccessMatchValue.WITH_COUNTRY,
                AccessMatchType.TYPE_EQUALCASE, "SE");
        final int zappPrimaryKey = AccessUserAspectData.generatePrimaryKey(role.getRoleName(), caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "Test");

        try {
            AccessUserAspectData bender = accessUserAspectManagerSession.create(role, caId, X500PrincipalAccessMatchValue.WITH_COUNTRY,
                    AccessMatchType.TYPE_EQUALCASE, "SE");
            // Also create a user without going via the session bean:
            AccessUserAspectData zapp = new AccessUserAspectData(role.getRoleName(), caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, "Test");
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(bender);
            subjects.add(zapp);
            role = roleManagementSession.addSubjectsToRole(authenticationToken, role, subjects);
            try {
                assertTrue(role.getAccessUsers().size() == 2);
                assertTrue(role.getAccessUsers().get(benderPrimaryKey).equals(bender));
                assertTrue(role.getAccessUsers().get(zappPrimaryKey).equals(zapp));

                // Modify a rule and add it again.
                subjects = new ArrayList<AccessUserAspectData>();
                bender.setMatchTypeAsValue(AccessMatchType.TYPE_NOT_EQUALCASE);
                subjects.add(bender);
                role = roleManagementSession.addSubjectsToRole(authenticationToken, role, subjects);
                assertTrue(role.getAccessUsers().size() == 2);
                assertTrue(role.getAccessUsers().get(benderPrimaryKey).equals(bender));
                assertTrue(role.getAccessUsers().get(zappPrimaryKey).equals(zapp));
                assertEquals(accessUserAspectManagerSession.find(benderPrimaryKey).getMatchTypeAsType(),
                        bender.getMatchTypeAsType());

            } finally {
                Collection<AccessUserAspectData> removeSubjects = new ArrayList<AccessUserAspectData>();
                removeSubjects.add(bender);
                role = roleManagementSession.removeSubjectsFromRole(authenticationToken, role, removeSubjects);
                AdminGroupData foundRole = roleAccessSession.findRole(role.getPrimaryKey());
                assertTrue(role.equals(foundRole));
                assertTrue(foundRole.getAccessUsers().size() == 1);
                assertTrue(role.getAccessUsers().get(zappPrimaryKey).equals(zapp));
            }

        } finally {
            roleManagementSession.remove(authenticationToken, role);
            assertNull("All user aspect where not removed when their attendant roles were.", accessRuleManagementSession.find(benderPrimaryKey));
        }
    }

    @Test
    public void testAddAndRemoveAccessRulesToRole() throws RoleExistsException, AccessRuleNotFoundException, AccessRuleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String ROLE_NAME = "ProfessorFarnsworth";
        final String RULE1 = "/future/rama";
        final String RULE2 = "/future/world";
        int accessRule1PrimaryKey = AccessRuleData.generatePrimaryKey(ROLE_NAME, RULE1);
        int accessRule2PrimaryKey = AccessRuleData.generatePrimaryKey(ROLE_NAME, RULE2);
        AccessRuleData accessRule1 = null;
        AccessRuleData accessRule2 = null;
        try {
            AdminGroupData role = roleManagementSession.create(authenticationToken, ROLE_NAME);
            assertTrue(ROLE_NAME.equals(role.getRoleName()));
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRule1 = accessRuleManagementSession.createRule(RULE1, role.getRoleName(), AccessRuleState.RULE_ACCEPT, true);

            accessRules.add(accessRule1);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);

            // Check the returned role
            assertTrue(role.getAccessRules().size() == 1);
            assertTrue(role.getAccessRules().get(accessRule1PrimaryKey).equals(accessRule1));

            AdminGroupData foundRole = roleAccessSession.findRole(role.getPrimaryKey());
            // Do the same check for a role retrieved from the database,
            assertTrue(foundRole.getAccessRules().size() == 1 && foundRole.getAccessRules().get(accessRule1PrimaryKey).equals(accessRule1));

            // Now modify futureRama
            accessRules = new ArrayList<AccessRuleData>();
            accessRule1.setInternalState(AccessRuleState.RULE_DECLINE);
            accessRules.add(accessRule1);

            // Add another rule, unpersisted, make sure that it's created
            accessRule2 = new AccessRuleData(role.getRoleName(), RULE2, AccessRuleState.RULE_ACCEPT, true);
            accessRules.add(accessRule2);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);

            // Check that both rules (and only those two) are there.
            Map<Integer, AccessRuleData> retrievedRules = roleAccessSession.findRole(role.getPrimaryKey()).getAccessRules();
            assertTrue(retrievedRules.size() == 2);
            assertEquals(accessRule1, retrievedRules.get(accessRule1PrimaryKey));
            assertEquals(accessRule2, retrievedRules.get(accessRule2PrimaryKey));

            // Remove one of rules
            Collection<AccessRuleData> deleteRules = new ArrayList<AccessRuleData>();
            deleteRules.add(accessRule1);
            role = roleManagementSession.removeAccessRulesFromRole(authenticationToken, role, deleteRules);
            retrievedRules = role.getAccessRules();
            assertTrue(retrievedRules.size() == 1);
            assertEquals(retrievedRules.get(accessRule2PrimaryKey), accessRule2);
            // Verify that futureRama has been removed entirely
            assertNull(accessRuleManagementSession.find(accessRule1PrimaryKey));

        } finally {
            roleManagementSession.remove(authenticationToken, ROLE_NAME);
            boolean accessRule1RemovedByRoleRemoval = true;
            if ((accessRule1=accessRuleManagementSession.find(accessRule1PrimaryKey)) != null) {
                // If the test failed adding the access rule to the role, it will not be removed when removing the role above
                accessRuleManagementSession.remove(accessRule1);
                accessRule1RemovedByRoleRemoval = false;
            }
            boolean accessRule2RemovedByRoleRemoval = true;
            if ((accessRule2=accessRuleManagementSession.find(accessRule2PrimaryKey)) != null) {
                // If the test failed adding the access rule to the role, it will not be removed when removing the role above
                accessRuleManagementSession.remove(accessRule2);
                accessRule2RemovedByRoleRemoval = false;
            }
            log.info("accessRule1RemovedByRoleRemoval: " + accessRule1RemovedByRoleRemoval);
            log.info("accessRule2RemovedByRoleRemoval: " + accessRule2RemovedByRoleRemoval);
            assertTrue("All rules where not removed when their attendant roles were.", accessRule1RemovedByRoleRemoval && accessRule2RemovedByRoleRemoval);
        }
    }

    @Test
    public void testAddAndRemoveTwoAccessRulesToRole() throws RoleExistsException, AccessRuleNotFoundException, AccessRuleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        final String ROLE_NAME = "ProfessorFarnsworth2";
        final String RULE1 = "/future/rama2";
        final String RULE2 = "/future/world2";
        int accessRule1PrimaryKey = AccessRuleData.generatePrimaryKey(ROLE_NAME, RULE1);
        int accessRule2PrimaryKey = AccessRuleData.generatePrimaryKey(ROLE_NAME, RULE2);
        AccessRuleData accessRule1 = null;
        AccessRuleData accessRule2 = null;
        try {
            AdminGroupData role = roleManagementSession.create(authenticationToken, ROLE_NAME);
            assertTrue(ROLE_NAME.equals(role.getRoleName()));
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRule1 = new AccessRuleData(role.getRoleName(), RULE1, AccessRuleState.RULE_ACCEPT, true);
            accessRule2 = new AccessRuleData(role.getRoleName(), RULE2, AccessRuleState.RULE_ACCEPT, true);

            accessRules.add(accessRule1);
            accessRules.add(accessRule2);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);

            // Check the returned role
            assertTrue(role.getAccessRules().size() == 2);
            assertTrue(role.getAccessRules().get(accessRule1PrimaryKey).equals(accessRule1));
            assertTrue(role.getAccessRules().get(accessRule2PrimaryKey).equals(accessRule2));

            AdminGroupData foundRole = roleAccessSession.findRole(role.getPrimaryKey());
            // Do the same check for a role retrieved from the database,
            assertTrue(foundRole.getAccessRules().size() == 2);
            assertTrue(foundRole.getAccessRules().get(accessRule1PrimaryKey).equals(accessRule1));
            assertTrue(foundRole.getAccessRules().get(accessRule2PrimaryKey).equals(accessRule2));

            // Now modify futureRama and futureWorld
            accessRules = new ArrayList<AccessRuleData>();
            accessRule1.setInternalState(AccessRuleState.RULE_DECLINE);
            accessRules.add(accessRule1);
            accessRule2.setInternalState(AccessRuleState.RULE_DECLINE);
            accessRules.add(accessRule2);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);

            // Check that both rules (and only those two) are there.
            Map<Integer, AccessRuleData> retrievedRules = roleAccessSession.findRole(role.getPrimaryKey()).getAccessRules();
            assertTrue(retrievedRules.size() == 2);
            assertEquals(accessRule1, retrievedRules.get(accessRule1PrimaryKey));
            assertEquals(accessRule2, retrievedRules.get(accessRule2PrimaryKey));

            // Remove both of rules
            Collection<AccessRuleData> deleteRules = new ArrayList<AccessRuleData>();
            deleteRules.add(accessRule1);
            deleteRules.add(accessRule2);
            role = roleManagementSession.removeAccessRulesFromRole(authenticationToken, role, deleteRules);
            retrievedRules = role.getAccessRules();
            assertTrue(retrievedRules.size() == 0);
            // Verify that futureRama and futureWorld has been removed entirely
            assertNull(accessRuleManagementSession.find(accessRule1PrimaryKey));
            assertNull(accessRuleManagementSession.find(accessRule2PrimaryKey));

        } finally {
            roleManagementSession.remove(authenticationToken, ROLE_NAME);
            boolean accessRule1RemovedByRoleRemoval = true;
            if ((accessRule1=accessRuleManagementSession.find(accessRule1PrimaryKey)) != null) {
                // If the test failed adding the access rule to the role, it will not be removed when removing the role above
                accessRuleManagementSession.remove(accessRule1);
                accessRule1RemovedByRoleRemoval = false;
            }
            boolean accessRule2RemovedByRoleRemoval = true;
            if ((accessRule2=accessRuleManagementSession.find(accessRule2PrimaryKey)) != null) {
                // If the test failed adding the access rule to the role, it will not be removed when removing the role above
                accessRuleManagementSession.remove(accessRule2);
                accessRule2RemovedByRoleRemoval = false;
            }
            log.info("accessRule1RemovedByRoleRemoval: " + accessRule1RemovedByRoleRemoval);
            log.info("accessRule2RemovedByRoleRemoval: " + accessRule2RemovedByRoleRemoval);
            assertTrue("All rules where not removed when their attendant roles were.", accessRule1RemovedByRoleRemoval && accessRule2RemovedByRoleRemoval);
        }
    }

    @Test
    public void testRemoveRulesByName() throws Exception {
        String roleName = "Skippy";
        String ruleName = "/planet/mercury";
        AdminGroupData role = roleManagementSession.create(authenticationToken, roleName);      

        try {
            Collection<AccessRuleData> rules = new ArrayList<AccessRuleData>();
            rules.add(new AccessRuleData(roleName, ruleName, AccessRuleState.RULE_ACCEPT, false));
            roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, rules);
            if(accessRuleManagementSession.find(AccessRuleData.generatePrimaryKey(roleName, ruleName)) == null) {
                throw new Exception("Rule was not created, can not continue test.");
            }
            List<String> accessRulesToRemove = new ArrayList<String>();
            accessRulesToRemove.add(null);
            accessRulesToRemove.add(ruleName);
            roleManagementSession.removeAccessRulesFromRole(alwaysAllowAuthenticationToken, role, accessRulesToRemove);
            assertTrue(accessRuleManagementSession.find(AccessRuleData.generatePrimaryKey(roleName, ruleName)) == null);
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, role);
        }
    }

    @Test
    public void testRenameRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        AdminGroupData kip = roleManagementSession.create(authenticationToken, "Kip");
        AdminGroupData cubert = roleManagementSession.create(authenticationToken, "Cubert");
        final int caId = 1337;
        
        Collection<AccessRuleData> accessRules = new LinkedList<AccessRuleData>();
        AccessRuleData accessRule = new AccessRuleData(kip.getRoleName(), "/TestRule", AccessRuleState.RULE_ACCEPT, false);
        accessRules.add(accessRule);
        kip = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, kip, accessRules);
        
        Collection<AccessUserAspectData> subjects = new LinkedList<AccessUserAspectData>();
        subjects.add(new AccessUserAspectData(kip.getRoleName(), caId,
            X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, "Kip"));
        kip = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, kip, subjects);

        try {
            kip = roleManagementSession.renameRole(authenticationToken, kip, "Amy");
            assertEquals("Amy", kip.getRoleName());
            assertEquals(kip, roleAccessSession.findRole("Amy"));
            assertNull(roleAccessSession.findRole("Kip"));
            
            // Try to edit the renamed role. The primary keys should have been updated.
            // We should NOT get "Role Amy did not match up with the role that created this rule." here
            accessRules = new ArrayList<AccessRuleData>(kip.getAccessRules().values());
            roleManagementSession.replaceAccessRulesInRole(authenticationToken, kip, accessRules);
            
            // Try renaming to an existing name
            boolean caught = false;
            try {
            roleManagementSession.renameRole(authenticationToken, kip, "Cubert");
            } catch (RoleExistsException e) {
                caught = true;
            }
            assertTrue(caught);
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, kip);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, cubert);
        }
    }
    
    /**
     * This test creates a role with two rules, one which will be replaced and the other removed because it isn't included new 
     * collection of rules to replace the old ones. Additionally, the new collection will contain a rule not existing previously,
     * which should be added. Lastly, the rule existing both before and after the operation should have its value changed to the 
     * new value provided. 
     * 
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     * @throws AccessRuleNotFoundException
     * @throws RoleNotFoundException
     */
    @Test
    public void testReplaceAccessRulesInRole() throws RoleExistsException, AuthorizationDeniedException, AccessRuleNotFoundException,
            RoleNotFoundException {
        AdminGroupData ralph = roleManagementSession.create(roleMgmgToken, "Ralph");
        try {
            Collection<AccessRuleData> accessRules = new LinkedList<AccessRuleData>();
            accessRules.add(new AccessRuleData(ralph.getRoleName(), "/ToBeMerged", AccessRuleState.RULE_ACCEPT, false));
            AccessRuleData toBeRemoved = new AccessRuleData(ralph.getRoleName(), "/ToBeRemoved", AccessRuleState.RULE_ACCEPT, false);
            accessRules.add(toBeRemoved);
            ralph = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, ralph, accessRules);
            accessRules = new LinkedList<AccessRuleData>();
            AccessRuleData toBeMerged = new AccessRuleData(ralph.getRoleName(), "/ToBeMerged", AccessRuleState.RULE_DECLINE, false);
            AccessRuleData toBeAdded = new AccessRuleData(ralph.getRoleName(), "/ToBeAdded", AccessRuleState.RULE_DECLINE, false);
            accessRules.add(toBeMerged);
            accessRules.add(toBeAdded);
            ralph = roleManagementSession.replaceAccessRulesInRole(roleMgmgToken, ralph, accessRules);
            assertNotNull("Rule to be merged was removed", ralph.getAccessRules().get(toBeMerged.getPrimaryKey()));
            assertEquals("Rule to be merged was not merged", AccessRuleState.RULE_DECLINE, ralph.getAccessRules().get(toBeMerged.getPrimaryKey()).getInternalState());
            assertNotNull("Rule to be added was not added", ralph.getAccessRules().get(toBeAdded.getPrimaryKey()));
            assertNull("Rule to be removed was not removed", ralph.getAccessRules().get(toBeRemoved.getPrimaryKey()));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, ralph);
        }
    }
    
    /**
     * This method tests isAuthorizedToEditRoleWithoutAspectAccess for a role not having access to that role's CA
     */
    @Test
    public void testIsAuthorizedToEditRoleWithoutCaAccess() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException,
            AccessUserAspectExistsException {
        final String unauthorizedRoleName = "Mom";
        final String unauthorizedRoleDn = "CN=Mom";
        final String authorizedRoleName = "Headless Body of Agnew";

        AdminGroupData unauthorizedRole = roleAccessSession.findRole(unauthorizedRoleName);
        if (unauthorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
        }
        unauthorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, unauthorizedRoleName);
        AdminGroupData authorizedRole = roleAccessSession.findRole(authorizedRoleName);
        if (authorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
        authorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, authorizedRoleName);
        final int caId = 1337;
        try {
            AccessUserAspectData unauthorizedRoleAspect = accessUserAspectManagerSession.create(unauthorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, unauthorizedRoleName);
            Collection<AccessUserAspectData> unauthorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            unauthorizedRoleSubjects.add(unauthorizedRoleAspect);
            unauthorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleSubjects);
            AccessUserAspectData authorizedRoleAspect = accessUserAspectManagerSession.create(authorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, authorizedRoleName);
            Collection<AccessUserAspectData> authorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            authorizedRoleSubjects.add(authorizedRoleAspect);
            authorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleSubjects);
            AuthenticationToken momAuthenticationToken = createAuthenticationToken(unauthorizedRoleDn);
            /* The authentication created for unauthorizedRole doesn't have access to the CA that created 
             * authorizedRole, hence authorization failure.
             */
            assertFalse("Authorization should have been denied", roleManagementSession.isAuthorizedToRole(momAuthenticationToken, authorizedRole));

        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
    }

    /**
     * This method tests isAuthorizedToEditRoleWithoutAspectAccess for a role that doesn't have access to another role's rules.
     * @throws AccessRuleExistsException 
     */
    @Test
    public void testIsAuthorizedToEditRoleWithoutRuleAccess() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException,
            AccessUserAspectExistsException, AccessRuleExistsException {
        final String unauthorizedRoleName = "Mom";
        final String unauthorizedRoleDn = "CN=Mom";
        final String authorizedRoleName = "Headless Body of Agnew";
        AuthenticationToken unauthorizedRoleAuthenticationToken = createAuthenticationToken(unauthorizedRoleDn);
        int caId = CertTools.getIssuerDN(((TestX509CertificateAuthenticationToken) unauthorizedRoleAuthenticationToken).getCertificate()).hashCode();
        AdminGroupData unauthorizedRole = roleAccessSession.findRole(unauthorizedRoleName);
        if (unauthorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
        }
        unauthorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, unauthorizedRoleName);
        AdminGroupData authorizedRole = roleAccessSession.findRole(authorizedRoleName);
        if (authorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
        authorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, authorizedRoleName);
        try {
            AccessUserAspectData unauthorizedRoleAspect = accessUserAspectManagerSession.create(unauthorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, unauthorizedRoleName);
            Collection<AccessUserAspectData> unauthorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            unauthorizedRoleSubjects.add(unauthorizedRoleAspect);
            unauthorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleSubjects);

            Collection<AccessRuleData> unauthorizedRoleRules = new ArrayList<AccessRuleData>();
            //We add the access to authorizedRole's CA to unauthorizedRole, that is tested in another test
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, StandardRules.CAACCESS.resource() + Integer.toString(caId),
                    AccessRuleState.RULE_ACCEPT, true));
            //We add the rule /bar to both roles just to check that vanilla authorization still works 
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, "/bar", AccessRuleState.RULE_ACCEPT, true));
            unauthorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleRules);

            Collection<AccessUserAspectData> authorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            authorizedRoleSubjects.add(accessUserAspectManagerSession.create(authorizedRole, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, authorizedRoleName));
            authorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleSubjects);
            // Just a quick check here that CA access works. Not a test per say, so no assert. 
            if (!roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole)) {
                throw new RuntimeException("Authorization should have been allowed");
            }

            Collection<AccessRuleData> authorizedRoleRules = new ArrayList<AccessRuleData>();
            authorizedRoleRules.add(accessRuleManagementSession.createRule("/bar", authorizedRoleName, AccessRuleState.RULE_ACCEPT, true));
            authorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleRules);
            //Just a quick check that authorization for common rules still works. Not a test per say, so no assert. 
            if (!roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole)) {
                throw new RuntimeException("Authorization should have been allowed");
            }

            //The important bit is here. We add a rule to authorizedRole that unauthorizedRole doesn't have access to. 
            Collection<AccessRuleData> newauthorizedRoleRules = new ArrayList<AccessRuleData>();
            newauthorizedRoleRules.add(accessRuleManagementSession.createRule("/foo", authorizedRoleName, AccessRuleState.RULE_ACCEPT, true));
            authorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, authorizedRole, newauthorizedRoleRules);
            //unAuthorizedRole doesn't have access to /foo, which authorizedRole does. 
            assertFalse("Authorization should have been denied." + " A role was given authorization for another role containing rules "
                    + "that that role itself didn't have access to.",
                    roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
    }
    
    /**
     * This is a regression test to check the usecase that came up in EJBCAINTER-37
     * 
     * Role A is a standard super admin with recursive access to "/"
     * Role B is a super admin with recursive access to "/" but is denied access to a certain rule "/foo"
     * Role C is a super admin with access to "/" and "/foo", but is identified by a weaker DN value
     * 
     * Role B should thus be unauthorized to edit A
     * 
     */
    @Test
    public void testIsAuthorizedToEditRoleWithDeniedRuleAccess() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException,
            AccessUserAspectExistsException, AccessRuleExistsException {
        final String unauthorizedRoleName = "RoleB";
        final String unauthorizedRoleDn = "C=SE,CN=RoleB";
        final String authorizedRoleName = "RoleA";
        final String weakRoleName = "RoleC";
        AuthenticationToken unauthorizedRoleAuthenticationToken = createAuthenticationToken(unauthorizedRoleDn);
        int caId = CertTools.getIssuerDN(((TestX509CertificateAuthenticationToken) unauthorizedRoleAuthenticationToken).getCertificate()).hashCode();
        AdminGroupData unauthorizedRole = roleAccessSession.findRole(unauthorizedRoleName);
        if (unauthorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
        }
        unauthorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, unauthorizedRoleName);
        AdminGroupData authorizedRole = roleAccessSession.findRole(authorizedRoleName);
        if (authorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
        authorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, authorizedRoleName);
        AdminGroupData weakRole = roleAccessSession.findRole(weakRoleName);
        if (weakRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, weakRole);
        }
        weakRole = roleManagementSession.create(alwaysAllowAuthenticationToken, weakRoleName);
        try {
            //Create rules for RoleB
            AccessUserAspectData unauthorizedRoleAspect = accessUserAspectManagerSession.create(unauthorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, unauthorizedRoleName);
            Collection<AccessUserAspectData> unauthorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            unauthorizedRoleSubjects.add(unauthorizedRoleAspect);
            unauthorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleSubjects);
            Collection<AccessRuleData> unauthorizedRoleRules = new ArrayList<AccessRuleData>();
            // Add the recursive access to root
            unauthorizedRoleRules
                    .add(new AccessRuleData(unauthorizedRoleName, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
            // Deny access to the rule "/foo", meaning that B lacks access to something that A may have access to 
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, "/foo", AccessRuleState.RULE_DECLINE, false));
            unauthorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleRules);
            
            // Create rules for RoleA
            Collection<AccessUserAspectData> authorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            authorizedRoleSubjects.add(accessUserAspectManagerSession.create(authorizedRole, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, authorizedRoleName));
            authorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleSubjects);
            // Just a quick check here that CA access works. Not a test per say, so no assert. 
            if (!roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole)) {
                throw new RuntimeException("Authorization should have been allowed");
            }
            Collection<AccessRuleData> authorizedRoleRules = new ArrayList<AccessRuleData>();
            authorizedRoleRules.add(accessRuleManagementSession.createRule("/", authorizedRoleName, AccessRuleState.RULE_ACCEPT, true));
            authorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleRules); 
            
            //Create rules for RoleC, a weaker role match than the above CN 
            AccessUserAspectData weakRoleAspect = accessUserAspectManagerSession.create(weakRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COUNTRY, AccessMatchType.TYPE_EQUALCASE, "SE");
            Collection<AccessUserAspectData> weakRoleSubjects = new ArrayList<AccessUserAspectData>();
            weakRoleSubjects.add(weakRoleAspect);
            weakRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, weakRole, weakRoleSubjects);
            Collection<AccessRuleData> weakRoleRules = new ArrayList<AccessRuleData>();
            weakRoleRules.add(new AccessRuleData(weakRoleName, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
            weakRoleRules.add(new AccessRuleData(weakRoleName, "/foo", AccessRuleState.RULE_ACCEPT, false));
            weakRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, weakRole, weakRoleRules);
          
            accessControlSession.forceCacheExpire();
            // Check privileges here. 
            assertFalse("Role was given access to another role even though denied resources available to that role.",
                    roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, weakRole);
        }
    }

    /**
     * This method tests isAuthorizedToEditRoleWithoutAspectAccess for a role that has access to another role's rule, but that
     * rule happens to be recursive and contain a subrule with status unknown.
     * @throws AccessRuleExistsException 
     */
    @Test
    public void testIsAuthorizedToEditRoleForRecursiveRuleAccessWithSubRule() throws RoleNotFoundException, AuthorizationDeniedException,
            RoleExistsException, AccessUserAspectExistsException, AccessRuleExistsException {
        final String unauthorizedRoleName = "Mom";
        final String unauthorizedRoleDn = "CN=Mom";
        final String authorizedRoleName = "Headless Body of Agnew";
        AuthenticationToken unauthorizedRoleAuthenticationToken = createAuthenticationToken(unauthorizedRoleDn);
        int caId = CertTools.getIssuerDN(((TestX509CertificateAuthenticationToken) unauthorizedRoleAuthenticationToken).getCertificate()).hashCode();
        AdminGroupData unauthorizedRole = roleAccessSession.findRole(unauthorizedRoleName);
        if (unauthorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
        }
        unauthorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, unauthorizedRoleName);
        AdminGroupData authorizedRole = roleAccessSession.findRole(authorizedRoleName);
        if (authorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
        authorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, authorizedRoleName);
        try {
            AccessUserAspectData unauthorizedRoleAspect = accessUserAspectManagerSession.create(unauthorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, unauthorizedRoleName);
            Collection<AccessUserAspectData> unauthorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            unauthorizedRoleSubjects.add(unauthorizedRoleAspect);
            unauthorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleSubjects);

            Collection<AccessRuleData> unauthorizedRoleRules = new ArrayList<AccessRuleData>();
            //We add the access to authorizedRole's CA to unauthorizedRole, that is tested in another test
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, StandardRules.CAACCESS.resource() + Integer.toString(caId),
                    AccessRuleState.RULE_ACCEPT, true));
            //We add the rule /bar to both roles just to check that vanilla authorization still works 
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, "/bar", AccessRuleState.RULE_ACCEPT, false));
            unauthorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleRules);

            Collection<AccessUserAspectData> authorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            authorizedRoleSubjects.add(accessUserAspectManagerSession.create(authorizedRole, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, authorizedRoleName));
            authorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleSubjects);
            // Just a quick check here that CA access works. Not a test per say, so no assert. 
            if (!roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole)) {
                throw new RuntimeException("Authorization should have been allowed");
            }

            Collection<AccessRuleData> authorizedRoleRules = new ArrayList<AccessRuleData>();
            authorizedRoleRules.add(new AccessRuleData(authorizedRoleName, "/bar", AccessRuleState.RULE_ACCEPT, true));
            authorizedRoleRules.add(new AccessRuleData(authorizedRoleName, "/bar/xyz", AccessRuleState.RULE_NOTUSED, false));
            authorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleRules);
            /*
             * unauthorizedRole does not have access to /bar/xyz
             */
            assertFalse("Unauthorized access to rule, had access to recursive subrule which should have been denied.",
                    roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
    }

    /**
     * This method tests isAuthorizedToEditRoleWithoutAspectAccess for a role that has access to another role's rule, but that
     * rule happens to be recursive. This test will run with recursive as false for a case when rule(+r) == rule(-r) can lead to 
     * privilege escalation. 
     */
    @Test
    public void testIsAuthorizedToEditRoleForRecursiveRuleAccess() throws RoleNotFoundException, AuthorizationDeniedException, RoleExistsException,
            AccessUserAspectExistsException, AccessRuleExistsException {
        final String unauthorizedRoleName = "Mom";
        final String unauthorizedRoleDn = "CN=Mom";
        final String authorizedRoleName = "Headless Body of Agnew";
        AuthenticationToken unauthorizedRoleAuthenticationToken = createAuthenticationToken(unauthorizedRoleDn);
        int caId = CertTools.getIssuerDN(((TestX509CertificateAuthenticationToken) unauthorizedRoleAuthenticationToken).getCertificate()).hashCode();
        AdminGroupData unauthorizedRole = roleAccessSession.findRole(unauthorizedRoleName);
        if (unauthorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
        }
        unauthorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, unauthorizedRoleName);
        AdminGroupData authorizedRole = roleAccessSession.findRole(authorizedRoleName);
        if (authorizedRole != null) {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
        authorizedRole = roleManagementSession.create(alwaysAllowAuthenticationToken, authorizedRoleName);
        try {
            AccessUserAspectData unauthorizedRoleAspect = accessUserAspectManagerSession.create(unauthorizedRole, caId,
                    X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, unauthorizedRoleName);
            Collection<AccessUserAspectData> unauthorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            unauthorizedRoleSubjects.add(unauthorizedRoleAspect);
            unauthorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleSubjects);

            Collection<AccessRuleData> unauthorizedRoleRules = new ArrayList<AccessRuleData>();
            //We add the access to authorizedRole's CA to unauthorizedRole, that is tested in another test
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, StandardRules.CAACCESS.resource() + Integer.toString(caId),
                    AccessRuleState.RULE_ACCEPT, true));
            //We add the rule /bar to both roles just to check that vanilla authorization still works 
            unauthorizedRoleRules.add(new AccessRuleData(unauthorizedRoleName, "/bar", AccessRuleState.RULE_ACCEPT, false));
            unauthorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, unauthorizedRole, unauthorizedRoleRules);

            Collection<AccessUserAspectData> authorizedRoleSubjects = new ArrayList<AccessUserAspectData>();
            authorizedRoleSubjects.add(accessUserAspectManagerSession.create(authorizedRole, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, authorizedRoleName));
            authorizedRole = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleSubjects);
            // Just a quick check here that CA access works. Not a test per say, so no assert. 
            if (!roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole)) {
                throw new RuntimeException("Authorization should have been allowed");
            }

            Collection<AccessRuleData> authorizedRoleRules = new ArrayList<AccessRuleData>();
            authorizedRoleRules.add(new AccessRuleData(authorizedRoleName, "/bar", AccessRuleState.RULE_ACCEPT, true));
            authorizedRole = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, authorizedRole, authorizedRoleRules);
            /*
             * unauthorizedRole does not have recursive access, while authorizedRole does. 
             */
            assertFalse("Unauthorized access to rule, had access to recursive rule without being recursive itself.",
                    roleManagementSession.isAuthorizedToRole(unauthorizedRoleAuthenticationToken, authorizedRole));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, unauthorizedRole);
            roleManagementSession.remove(alwaysAllowAuthenticationToken, authorizedRole);
        }
    }
    
}
