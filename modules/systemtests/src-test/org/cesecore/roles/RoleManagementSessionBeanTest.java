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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
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
import org.cesecore.jndi.JndiHelper;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Based on cesecore version:
 *      RoleManagementSessionBeanTest.java 561 2011-03-15 16:15:28Z mikek
 * 
 * @version $Id$
 * 
 */
public class RoleManagementSessionBeanTest extends RoleUsingTestCase {

    private AccessRuleManagementTestSessionRemote accessRuleManagementSession = JndiHelper.getRemoteSession(AccessRuleManagementTestSessionRemote.class);
    private AccessUserAspectManagerTestSessionRemote accessUserAspectManagerSession = JndiHelper
            .getRemoteSession(AccessUserAspectManagerTestSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    
    private AuthenticationToken authenticationToken;
   

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

        RoleData role = null;
        final String roleName = "Nibbler";
        RoleData foundRole = null;
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

        RoleData role = roleManagementSession.create(authenticationToken, roleName);
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

        Collection<RoleData> roles = roleAccessSession.getAllRoles();
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
        RoleData role = roleManagementSession.create(authenticationToken, "Zoidberg");
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
                RoleData foundRole = roleAccessSession.findRole(role.getPrimaryKey());
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
        RoleData role = roleManagementSession.create(authenticationToken, "ProfessorFarnsworth");
        int futureRamaPrimaryKey = AccessRuleData.generatePrimaryKey(role.getRoleName(), "/future/rama");
        int futureWorldPrimaryKey = AccessRuleData.generatePrimaryKey(role.getRoleName(), "/future/world");

        try {
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            AccessRuleData futureRama = accessRuleManagementSession.createRule("/future/rama", role.getRoleName(), AccessRuleState.RULE_ACCEPT, true);

            accessRules.add(futureRama);
            role = roleManagementSession.addAccessRulesToRole(authenticationToken, role, accessRules);

            // Check the returned role
            assertTrue(role.getAccessRules().size() == 1);
            assertTrue(role.getAccessRules().get(futureRamaPrimaryKey).equals(futureRama));

            RoleData foundRole = roleAccessSession.findRole(role.getPrimaryKey());
            // Do the same check for a role retrieved from the database,
            assertTrue(foundRole.getAccessRules().size() == 1 && foundRole.getAccessRules().get(futureRamaPrimaryKey).equals(futureRama));

            // Now modify futureRama
            accessRules = new ArrayList<AccessRuleData>();
            futureRama.setInternalState(AccessRuleState.RULE_DECLINE);
            accessRules.add(futureRama);

            // Add another rule, unpersisted, make sure that it's created
            AccessRuleData futureWorld = new AccessRuleData(role.getRoleName(), "/future/world", AccessRuleState.RULE_ACCEPT, true);
            accessRules.add(futureWorld);
            role = roleManagementSession.addAccessRulesToRole(authenticationToken, role, accessRules);

            // Check that both rules (and only those two) are there.
            Map<Integer, AccessRuleData> retrievedRules = roleAccessSession.findRole(role.getPrimaryKey()).getAccessRules();
            assertTrue(retrievedRules.size() == 2);
            assertEquals(retrievedRules.get(futureRamaPrimaryKey), futureRama);
            assertEquals(retrievedRules.get(futureWorldPrimaryKey), futureWorld);

            // Remove one of rules
            Collection<AccessRuleData> deleteRules = new ArrayList<AccessRuleData>();
            deleteRules.add(futureRama);
            role = roleManagementSession.removeAccessRulesFromRole(authenticationToken, role, deleteRules);
            retrievedRules = role.getAccessRules();
            assertTrue(retrievedRules.size() == 1);
            assertEquals(retrievedRules.get(futureWorldPrimaryKey), futureWorld);
            // Verify that futureRama has been removed entirely
            assertNull(accessRuleManagementSession.find(futureRamaPrimaryKey));

        } finally {
            roleManagementSession.remove(authenticationToken, role);
            assertNull("All rules where not removed when their attendant roles were.", accessRuleManagementSession.find(futureWorldPrimaryKey));
        }
    }
    
    @Test
    public void testRemoveRulesByName() throws Exception {
        String roleName = "Skippy";
        String ruleName = "/planet/mercury";
        RoleData role = roleManagementSession.create(authenticationToken, roleName);      

        try {
            Collection<AccessRuleData> rules = new ArrayList<AccessRuleData>();
            rules.add(new AccessRuleData(roleName, ruleName, AccessRuleState.RULE_ACCEPT, false));
            roleManagementSession.addAccessRulesToRole(authenticationToken, role, rules);
            if(accessRuleManagementSession.find(AccessRuleData.generatePrimaryKey(roleName, ruleName)) == null) {
                throw new Exception("Rule was not created, can not continue test.");
            }
            List<String> accessRulesToRemove = new ArrayList<String>();
            accessRulesToRemove.add(null);
            accessRulesToRemove.add(ruleName);
            roleManagementSession.removeAccessRulesFromRole(authenticationToken, role, accessRulesToRemove);
            assertTrue(accessRuleManagementSession.find(AccessRuleData.generatePrimaryKey(roleName, ruleName)) == null);
        } finally {
            roleManagementSession.remove(authenticationToken, role);
        }
    }

    @Test
    public void testRenameRole() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        RoleData kip = roleManagementSession.create(authenticationToken, "Kip");
        RoleData cubert = roleManagementSession.create(authenticationToken, "Cubert");

        try {
            kip = roleManagementSession.renameRole(authenticationToken, kip, "Amy");
            assertEquals("Amy", kip.getRoleName());
            assertEquals(kip, roleAccessSession.findRole("Amy"));
            boolean caught = false;
            try {
            roleManagementSession.renameRole(authenticationToken, kip, "Cubert");
            } catch (RoleExistsException e) {
                caught = true;
            }
            assertTrue(caught);
        } finally {
            roleManagementSession.remove(authenticationToken, kip);
            roleManagementSession.remove(authenticationToken, cubert);
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
        RoleData ralph = roleManagementSession.create(roleMgmgToken, "Ralph");
        try {
            Collection<AccessRuleData> accessRules = new LinkedList<AccessRuleData>();
            accessRules.add(new AccessRuleData(ralph.getRoleName(), "/ToBeMerged", AccessRuleState.RULE_ACCEPT, false));
            AccessRuleData toBeRemoved = new AccessRuleData(ralph.getRoleName(), "/ToBeRemoved", AccessRuleState.RULE_ACCEPT, false);
            accessRules.add(toBeRemoved);
            ralph = roleManagementSession.addAccessRulesToRole(roleMgmgToken, ralph, accessRules);
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
            roleManagementSession.remove(roleMgmgToken, ralph);
        }
    }
}
