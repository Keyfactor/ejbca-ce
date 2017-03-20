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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * System test of RoleSessionBean.
 * 
 * @version $Id$
 */
public class RoleSessionBeanTest {
    
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final Logger log = Logger.getLogger(RoleSessionBeanTest.class);

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AuthorizationSessionBeanTest"));

    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final Role cleanUpRole = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace, roleName);
        if (cleanUpRole!=null) {
            roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, cleanUpRole.getRoleId());
        }
    }
    
    /**
     * Basic sanity test for role operations
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testCrud() throws RoleExistsException, AuthorizationDeniedException {
        cleanUpRole(null, "RoleSessionBeanTest.testCrud");
        // Create
        final Role role = new Role(null, "RoleSessionBeanTest.testCrud");
        role.getAccessRules().put("/", Role.STATE_ALLOW);
        final Role createdRole = roleSession.persistRole(alwaysAllowAuthenticationToken, role);
        assertFalse(Role.ROLE_ID_UNASSIGNED == createdRole.getRoleId());
        assertEquals(role.getNameSpace(), createdRole.getNameSpace());
        assertEquals(role.getRoleName(), createdRole.getRoleName());
        assertEquals(role.getAccessRules().size(), createdRole.getAccessRules().size());
        // Read
        final Role fetchedRole = roleSession.getRole(alwaysAllowAuthenticationToken, createdRole.getRoleId());
        assertEquals(createdRole.getRoleId(), fetchedRole.getRoleId());
        assertEquals(createdRole.getNameSpace(), fetchedRole.getNameSpace());
        assertEquals(createdRole.getRoleName(), fetchedRole.getRoleName());
        assertEquals(createdRole.getAccessRules().size(), fetchedRole.getAccessRules().size());
        // Update (including renaming and change of namespace)
        fetchedRole.getAccessRules().put("/a/b", Role.STATE_DENY);
        fetchedRole.setRoleName(fetchedRole.getRoleName() + " (renamed)");
        fetchedRole.setNameSpace("companyx");
        final Role updatedRole = roleSession.persistRole(alwaysAllowAuthenticationToken, fetchedRole);
        assertEquals(fetchedRole.getRoleId(), updatedRole.getRoleId());
        assertEquals(fetchedRole.getNameSpace(), updatedRole.getNameSpace());
        assertEquals(fetchedRole.getRoleName(), updatedRole.getRoleName());
        assertEquals(fetchedRole.getAccessRules().size(), updatedRole.getAccessRules().size());
        // Delete
        assertTrue("Unable to delete the role created by this test.", roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, createdRole.getRoleId()));
    }

    /**
     * Expects exception thrown while adding two roles with identical namespace and role name combination
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testNameConflict() throws RoleExistsException, AuthorizationDeniedException {
        cleanUpRole(null, "RoleSessionBeanTest.testConflict");
        // Create
        final Role role1 = new Role(null, "RoleSessionBeanTest.testConflict");
        role1.getAccessRules().put("/", Role.STATE_ALLOW);
        roleSession.persistRole(alwaysAllowAuthenticationToken, role1);
        assertNotNull(roleSession.getRole(alwaysAllowAuthenticationToken, null, "RoleSessionBeanTest.testConflict"));
        final Role role2 = new Role(null, "RoleSessionBeanTest.testConflict");
        role2.getAccessRules().put("/", Role.STATE_ALLOW);
        try {
            roleSession.persistRole(alwaysAllowAuthenticationToken, role2);
            fail("Should not have been able to create 2 roles with the same nameSpace + roleName combination.");
        } catch (RoleExistsException e) {
            
        }
        cleanUpRole(null, "RoleSessionBeanTest.testConflict");
    }
    
    /**
     * Attempts renaming a role and assumes the role remains persisted with the same roleId 
     * but with a new name
     * @throws AuthorizationDeniedException
     * @throws RoleExistsException
     */
    @Test
    public void testRenameRole() throws AuthorizationDeniedException, RoleExistsException {
        final String defaultName = "RoleSessionBeanTest.testRename";
        final String newName = "RoleSessionBeanTest.testRenamedRole";
        cleanUpRole(null, defaultName);
        cleanUpRole(null, newName);
        //Set up role
        Role roleToRename = new Role(null, defaultName);
        roleToRename = roleSession.persistRole(alwaysAllowAuthenticationToken, roleToRename);
        int persistedRoleId = roleToRename.getRoleId();
        //Rename
        roleToRename.setRoleName(newName);
        roleSession.persistRole(alwaysAllowAuthenticationToken, roleToRename);
        //Get persisted role and verify id + name change
        Role retrievedRole = roleSession.getRole(alwaysAllowAuthenticationToken, roleToRename.getRoleId());
        assertEquals(retrievedRole.getRoleId(), roleToRename.getRoleId());
        assertEquals(retrievedRole.getRoleName(), newName);
        cleanUpRole(null, defaultName);
        cleanUpRole(null, newName);
    }
    
    /**
     * Tests basic behavior while editing access rules for roles.
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testAddAndRemoveAccessRulesToRole() throws AuthorizationDeniedException {
        cleanUpRole(null, "RoleSessionBeanTest.testAddRemoveAccess");
        //Create
        final String ROLE_NAME = "RoleSessionBeanTest.testAddRemoveAccess";
        final String RULE1 = "/future/rama";
        final String RULE2 = "/future/world";
        Role role = null;

        try {
            role = new Role(null, ROLE_NAME);
            assertTrue(ROLE_NAME.equals(role.getRoleName()));

            role.getAccessRules().put(RULE1, Role.STATE_ALLOW);
            role = roleSession.persistRole(alwaysAllowAuthenticationToken, role);

            // Check the returned role
            assertEquals(1 ,role.getAccessRules().size());
            assertEquals(Role.STATE_ALLOW, role.getAccessRules().get(AccessRulesHelper.normalizeResource(RULE1)));   
          
            // Do the same check for a role retrieved from the database,
            Role foundRole = roleSession.getRole(alwaysAllowAuthenticationToken, role.getRoleId());
            assertEquals(1, foundRole.getAccessRules().size());
            assertEquals(Role.STATE_ALLOW, foundRole.getAccessRules().get(AccessRulesHelper.normalizeResource(RULE1)));

            // Add another rule
            role.getAccessRules().put(RULE2, Role.STATE_ALLOW);
            role = roleSession.persistRole(alwaysAllowAuthenticationToken, role);

            // Check that both rules (and only those two) are there.
            LinkedHashMap<String, Boolean> retrievedRules = roleSession.getRole(alwaysAllowAuthenticationToken, role.getRoleId()).getAccessRules();
            assertEquals(2, retrievedRules.size());
            assertEquals(Role.STATE_ALLOW, retrievedRules.get(AccessRulesHelper.normalizeResource(RULE1)));
            assertEquals(Role.STATE_ALLOW, retrievedRules.get(AccessRulesHelper.normalizeResource(RULE2)));

            // Remove one of rules
            role.getAccessRules().remove(AccessRulesHelper.normalizeResource(RULE1));
            role = roleSession.persistRole(alwaysAllowAuthenticationToken, role);
            
            //Verify database commit
            retrievedRules = role.getAccessRules();
            assertTrue(retrievedRules.size() == 1);
            assertEquals(Role.STATE_ALLOW, retrievedRules.get(AccessRulesHelper.normalizeResource(RULE2)));

            // Verify that futureRama has been removed entirely
            assertNull(role.getAccessRules().get(AccessRulesHelper.normalizeResource(RULE1)));

        } catch (RoleExistsException e) {
            fail("Attempt to add a role: " + role.getRoleName() + " fail because it already exists. Is the database clean?");
        } finally {
            cleanUpRole(null, "RoleSessionBeanTest.testAddRemoveAccess");
        }
    }
    
    /**
     * Creates two roles, one authorized to edit roles and the other unauthorized to edit roles.
     * Each role retrieves a corresponding AuthenticationToken. The unauthorized role attempts to
     * delete the authorized role, using an unauthorized token. AuthorizationDeniedException is expected.
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToEditRoleWithoutRuleAccess() throws RoleExistsException, AuthorizationDeniedException {
        final String authRoleName = "AuthRole";
        final String unAuthRoleName ="UnAuthRole";
        final String authDN = "CN=AccessTest";
        Role authRole = new Role(null, authRoleName);
        Role unAuthRole = new Role(null, unAuthRoleName);
        cleanUpRole(null, authRoleName);
        cleanUpRole(null, unAuthRoleName);
        List<String> accessRules = Arrays.asList(StandardRules.EDITROLES.toString());
        
        //Create tokens representing access rules of created roles
        AuthenticationToken authToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, authRole.getRoleName(), accessRules, null);
        AuthenticationToken unAuthToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, unAuthRoleName, null, accessRules);
        
        authRole = roleSession.getRole(authToken, null, authRoleName);
        unAuthRole = roleSession.getRole(unAuthToken, null, unAuthRoleName);
        assertNotNull(authRole);
        assertNotNull(unAuthRole);
        
        //Test edit. AuthorizationDeniedException is expected
        try {
            roleSession.deleteRoleIdempotent(unAuthToken, authRole.getRoleId());
            fail("Was able to edit role without proper authorization");
        } finally {
            cleanUpRole(null, authRoleName);
            cleanUpRole(null, unAuthRoleName);
        }
    }
    
    /**
     * Test to make sure admin roles cannot view other admin roles with higher privileges 
     * @throws AuthorizationDeniedException
     * @throws RoleExistsException
     */
    @Test
    public void testGetAuthorizedRoles() throws AuthorizationDeniedException, RoleExistsException {
        final String someDN = "CN=SomeDN";
        final String strongAdminRoleName = "StrongAdmin";
        final String weakAdminRoleName = "WeakAdmin";
        List<String> strongRules = Arrays.asList("/", "/bar/foo");
        List<String> weakRules = Arrays.asList("/");
        List<String> weakDeniedRules = Arrays.asList("/bar/foo");

        try {
            AuthenticationToken strongToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(someDN, null, strongAdminRoleName, strongRules, null);
            AuthenticationToken weakToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(someDN, null, weakAdminRoleName, weakRules, weakDeniedRules);
            Role strongRole = roleSession.getRole(alwaysAllowAuthenticationToken, null, strongAdminRoleName);
            Role weakRole = roleSession.getRole(alwaysAllowAuthenticationToken, null, weakAdminRoleName);
            List<Role> strongAuthorizedRoles = roleSession.getAuthorizedRoles(strongToken);
            List<Role> weakAuthorizedRoles = roleSession.getAuthorizedRoles(weakToken);
            for (Role role : weakAuthorizedRoles) {
                log.info(role.getRoleName());
            }
            assertTrue(strongAuthorizedRoles.contains(weakRole));
            assertTrue(strongAuthorizedRoles.contains(strongRole));
            assertTrue(weakAuthorizedRoles.contains(weakRole));
            assertFalse(weakAuthorizedRoles.contains(strongRole));
            
        } finally {
            cleanUpRole(null, strongAdminRoleName);
            cleanUpRole(null, weakAdminRoleName);
        }
    }
    
    /**
     * Tests if an admin can view admins within different namespaces. This should not be possible
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testGetAuthorizedNamespaces() throws RoleExistsException, AuthorizationDeniedException {
        final String allowedNameSpace = "TestAllowedNameSpace";
        final String deniedNameSpace = "TestDeniedNameSpace";
        final String authDN = "CN=AuthDN";
        final String unAuthDN = "CN=UnAuthDN";
        final String adminRoleName = "AdminRole";
        final String anotherAdminRoleName = "AnotherAdminRole";
        
        AuthenticationToken adminToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(authDN, allowedNameSpace, adminRoleName, null, null);
        AuthenticationToken anotherAdminToken = roleInitSession.createAuthenticationTokenAndAssignToNewRole(unAuthDN, deniedNameSpace, anotherAdminRoleName, null, null);
        
        try {
            List<String> authorizedNameSpaces = roleSession.getAuthorizedNamespaces(adminToken);
            assertEquals(1, authorizedNameSpaces.size());
            assertEquals(allowedNameSpace , authorizedNameSpaces.get(0));
        } finally {
            cleanUpRole(allowedNameSpace, adminRoleName);
            cleanUpRole(deniedNameSpace, anotherAdminRoleName);
        }
    }
}