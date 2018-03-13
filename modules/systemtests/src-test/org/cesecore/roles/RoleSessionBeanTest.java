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
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * System test of RoleSessionBean.
 * 
 * @version $Id$
 */
public class RoleSessionBeanTest {
    
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleInitializationSessionRemote roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final Logger log = Logger.getLogger(RoleSessionBeanTest.class);

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(RoleSessionBeanTest.class.getSimpleName());

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
            assertEquals(1, retrievedRules.size());
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
        AuthenticationToken authToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, authRole.getRoleName(), accessRules, null);
        AuthenticationToken unAuthToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, unAuthRoleName, null, accessRules);
        
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

    /** Verify that an administrator cannot edit a Role that is providing all its access */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToNotEditOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToNotEditOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        final Role role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            role.getAccessRules().clear();
            role.getAccessRules().put(StandardRules.CAACCESS.resource(), Role.STATE_ALLOW);
            roleSession.persistRole(authenticationToken, role);
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator cannot reduce it's own namespace access */
    public void testIsNotAuthorizedToChangeNamespaceOfOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsNotAuthorizedToChangeNamespaceOfOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        Role role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        try {
            role.setNameSpace("PrimeKey"); // limit to 'PrimeKey'
            try {
                roleSession.persistRole(authenticationToken, role);
            } catch (AuthorizationDeniedException e) { } // NOPMD expected
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator cannot remove the Role that is providing all its access */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToNotDeleteOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToNotDeleteOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final Role role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            roleSession.deleteRoleIdempotent(authenticationToken, role.getRoleId());
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator cannot remove the RoleMember that is providing all its access */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToNotDeleteOwnRoleMember() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToNotDeleteOwnRoleMember";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final Role role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            final RoleMember roleMember = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role.getRoleId()).get(0);
            roleMemberSession.remove(authenticationToken, roleMember.getId());
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator can remove the Role that is providing redundant access */
    public void testIsAuthorizedToDeleteOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToDeleteOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            final Role role1 = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
            final List<RoleMember> roleMembers1 = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role1.getRoleId());
            final Role role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(null, TESTNAME+"2", Arrays.asList(StandardRules.CAACCESS.resource()), null));
            final RoleMember roleMember2 = new RoleMember(roleMembers1.get(0));
            roleMember2.setId(RoleMember.ROLE_MEMBER_ID_UNASSIGNED);
            roleMember2.setRoleId(role2.getRoleId());
            roleMemberSession.persist(alwaysAllowAuthenticationToken, roleMember2);
            try {
                roleSession.deleteRoleIdempotent(authenticationToken, role1.getRoleId());
            } catch (AuthorizationDeniedException e) {
                fail("Unable to delete Role that provides redundant access: " +e.getMessage());
            }
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator can remove the Role that is providing redundant access */
    public void testIsAuthorizedToDeleteOwnRoleMember() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToDeleteOwnRoleMember";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            final Role role1 = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
            final List<RoleMember> roleMembers1 = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role1.getRoleId());
            final Role role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(null, TESTNAME+"2", Arrays.asList(StandardRules.CAACCESS.resource()), null));
            final RoleMember roleMember2 = new RoleMember(roleMembers1.get(0));
            roleMember2.setId(RoleMember.ROLE_MEMBER_ID_UNASSIGNED);
            roleMember2.setRoleId(role2.getRoleId());
            roleMemberSession.persist(alwaysAllowAuthenticationToken, roleMember2);
            try {
                roleMemberSession.remove(authenticationToken, roleMembers1.get(0).getId());
            } catch (AuthorizationDeniedException e) {
                fail("Unable to delete RoleMember that provides redundant access: " +e.getMessage());
            } finally {
                roleSession.deleteRoleIdempotent(authenticationToken, role1.getRoleId());
            }
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
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
            AuthenticationToken strongToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(someDN, null, strongAdminRoleName, strongRules, null);
            AuthenticationToken weakToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(someDN, null, weakAdminRoleName, weakRules, weakDeniedRules);
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

    /** Verify that rename and reassigning to a different namespace works (and leaves no duplication behind) */
    @Test
    public void testRename() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testRename";
        final String roleName1 = TESTNAME + "Role1";
        final String nameSpace1 = TESTNAME + "NameSpace1";
        final String roleName2 = TESTNAME + "Role2";
        final String nameSpace2 = TESTNAME + "NameSpace2";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+roleName1, nameSpace1, roleName1, Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        try {
            final Role role = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace1, roleName1);
            role.setRoleName(roleName2);
            final Role roleUpdate1 = roleSession.persistRole(alwaysAllowAuthenticationToken, role);
            assertEquals(role.getRoleId(), roleUpdate1.getRoleId());
            assertNull(roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace1, roleName1));
            roleUpdate1.setNameSpace(nameSpace2);
            final Role roleUpdate2 = roleSession.persistRole(alwaysAllowAuthenticationToken, roleUpdate1);
            assertEquals(role.getRoleId(), roleUpdate2.getRoleId());
            assertNull(roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace2, roleName1));
            assertNotNull(roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace2, roleName2));
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /**
     * Verify name space handling:
     * - Admins should be able to see the namespaces of all roles they are part of
     * - Admin belonging to empty namespace should see all namespaces of roles the admin is authorized to
     *   (which implies access to all members' tokenIssuerIds)
     * - Otherwise namespaces should not be visible
     */
    @Test
    public void testGetAuthorizedNamespaces() throws RoleExistsException, AuthorizationDeniedException {
        log.trace(">testGetAuthorizedNamespaces");
        final String TESTNAME = "testGetAuthorizedNamespaces";
        final String nameSpace1 = TESTNAME + " NameSpace 1";
        final String nameSpace2 = TESTNAME + " NameSpace 2";
        final String nameSpace3 = TESTNAME + " NameSpace 3";
        final String nameSpace4 = "";
        final String commonRoleName = TESTNAME + "Role";
        final String subjectDn1 = "CN="+nameSpace1;
        final TestX509CertificateAuthenticationToken authenticationToken1 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                subjectDn1, nameSpace1, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken2 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace2, nameSpace2, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken3 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace3, nameSpace3, commonRoleName, Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken4 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace4, nameSpace4, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3), null, false);
            // Authentication token matching RoleMember that belongs to Role with empty name space should see all namespaces
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace4),
                    Arrays.asList(nameSpace3), true);
            // Add authenticationToken1 matched by CN to Role 2 (with nameSpace2)
            addRoleMemberToRole(nameSpace2, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2), null, false);
            // And again, add authenticationToken1 matched by CN to Role 3 (with nameSpace3)
            RoleMember roleMember = addRoleMemberToRole(nameSpace3, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2, nameSpace3), null, false);
            // Sanity check that adding authenticationToken1 did not grant more access to the other authenticationTokens
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace4),
                    Arrays.asList(nameSpace3), true);
            // Remove authenticationToken1 matched by CN from Role 3 (with nameSpace3) and expect that this namespace is no longer available
            roleMemberSession.remove(alwaysAllowAuthenticationToken, roleMember.getId());
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2), null, false);
            // Grant additional access to authenticationToken4 and expect that namespace3 will now also be visible
            final Role role4 = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4, commonRoleName);
            role4.getAccessRules().put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace3, nameSpace4), null, true);
            // Revoke additional access from authenticationToken4 and expect that namespace3 will no longer be visible
            final Role role4b = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4, commonRoleName);
            role4b.getAccessRules().clear();
            role4b.getAccessRules().put(StandardRules.CAACCESS.resource(), Role.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace4), null, true);
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken1);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken2);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken3);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken4);
            log.trace("<testGetAuthorizedNamespaces");
        }
    }

    /**
     * Verify name space handling when Roles are reassigned to different namespaces:
     * - Admins should be able to see the namespaces of all roles they are part of
     * - Admin belonging to empty namespace should see all namespaces of roles the admin is authorized to
     *   (which implies access to all members' tokenIssuerIds)
     * - Otherwise namespaces should not be visible
     */
    @Test
    public void testGetAuthorizedNamespacesAfterReassign() throws RoleExistsException, AuthorizationDeniedException {
        log.trace(">testGetAuthorizedNamespaces");
        final String TESTNAME = "testGetAuthorizedNamespaces";
        final String nameSpace1a = TESTNAME + " NameSpace 1a";
        final String nameSpace2a = TESTNAME + " NameSpace 2a";
        final String nameSpace3a = TESTNAME + " NameSpace 3a";
        final String nameSpace1b = TESTNAME + " NameSpace 1b";
        final String nameSpace2b = TESTNAME + " NameSpace 2b";
        final String nameSpace3b = TESTNAME + " NameSpace 3b";
        final String nameSpace4a = "";
        final String nameSpace4b = TESTNAME + " NameSpace 4b";
        final String commonRoleName = TESTNAME + "Role";
        final String subjectDn1 = "CN="+nameSpace1a;
        final TestX509CertificateAuthenticationToken authenticationToken1 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                subjectDn1, nameSpace1a, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken2 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace2a, nameSpace2a, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken3 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace3a, nameSpace3a, commonRoleName, Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        final TestX509CertificateAuthenticationToken authenticationToken4 = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(
                "CN="+nameSpace4a, nameSpace4a, commonRoleName, Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace1a, nameSpace1b);
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace2a, nameSpace2b);
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace3a, nameSpace3b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3b), null, false);
            // Authentication token matching RoleMember that belongs to Role with empty name space should see all namespaces
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace3b, nameSpace1a, nameSpace2a, nameSpace3a), true);
            // Add authenticationToken1 matched by CN to Role 2 (with nameSpace2)
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace2b, nameSpace2a);
            addRoleMemberToRole(nameSpace2a, commonRoleName, subjectDn1);
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace2a, nameSpace2b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b),
                    Arrays.asList(nameSpace1a, nameSpace2a), false);
            // And again, add authenticationToken1 matched by CN to Role 3 (with nameSpace3)
            RoleMember roleMember = addRoleMemberToRole(nameSpace3b, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace3b),
                    Arrays.asList(nameSpace1a, nameSpace2a, nameSpace3a), false);
            // Sanity check that adding authenticationToken1 did not grant more access to the other authenticationTokens
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace3b), true);
            // Remove authenticationToken1 matched by CN from Role 3 (with nameSpace3) and expect that this namespace is no longer available
            roleMemberSession.remove(alwaysAllowAuthenticationToken, roleMember.getId());
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b),
                    Arrays.asList(nameSpace1a, nameSpace2a), false);
            // Grant additional access to authenticationToken4 and expect that namespace3 will now also be visible
            final Role role4 = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4a, commonRoleName);
            role4.getAccessRules().put(StandardRules.ROLE_ROOT.resource(), Role.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace3b, nameSpace4a),
                    Arrays.asList(nameSpace1a, nameSpace2a, nameSpace3a), true);
            // Revoke additional access from authenticationToken4 and expect that namespace3 will no longer be visible
            final Role role4b = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4a, commonRoleName);
            role4b.getAccessRules().clear();
            role4b.getAccessRules().put(StandardRules.CAACCESS.resource(), Role.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace1a, nameSpace2a), true);
            // Verify that move from empty namespace4a to non-empty namespace4b will prevent access to other namespaces
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace4a, nameSpace4b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace4b),
                    Arrays.asList(nameSpace1a, nameSpace2a, nameSpace1b, nameSpace2b, nameSpace4a), false);
            // ...and moving back should restore access
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace4b, nameSpace4a);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace1a, nameSpace2a), true);
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken1);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken2);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken3);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken4);
            log.trace("<testGetAuthorizedNamespaces");
        }
    }
    
    /** Move a Role from one name space to another */
    private void reassignRoleToDifferentNameSpace(final String roleName, final String oldNameSpace, final String newNameSpace) throws AuthorizationDeniedException, RoleExistsException {
        final Role role = roleSession.getRole(alwaysAllowAuthenticationToken, oldNameSpace, roleName);
        role.setNameSpace(newNameSpace);
        roleSession.persistRole(alwaysAllowAuthenticationToken, role);
    }

    /** Add self signed certificate match to a role identified by name and return the persisted RoleMember */
    private RoleMember addRoleMemberToRole(final String nameSpace, final String roleName, final String subjectDn) throws AuthorizationDeniedException {
        final Role role = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace, roleName);
        return roleMemberSession.persist(alwaysAllowAuthenticationToken, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                subjectDn.hashCode(), X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), subjectDn, role.getRoleId(), null));
        
    }
    
    /** Verify that actualNameSpaces contain the desired namespaces */
    private void assertNameSpacePresence(List<String> actualNameSpaces, List<String> requiredNameSpaces, List<String> notAllowedNameSpaces, boolean allowMoreNameSpaces) {
        log.debug("actualNameSpaces: " + Arrays.toString(actualNameSpaces.toArray()));
        if (requiredNameSpaces!=null) {
            log.debug("requiredNameSpaces: " + Arrays.toString(requiredNameSpaces.toArray()) + " allowMoreNameSpaces="+allowMoreNameSpaces);
            if (allowMoreNameSpaces) {
                assertTrue("Admin should at least belong to " + requiredNameSpaces.size() + " namespace(s).", actualNameSpaces.size() >= requiredNameSpaces.size());
            } else {
                assertEquals("Admin should at belong to " + requiredNameSpaces.size() + " namespace(s).", requiredNameSpaces.size(), actualNameSpaces.size());
            }
            for (final String requiredNameSpace : requiredNameSpaces) {
                assertTrue("Not authorized to expected name space '" + requiredNameSpace + "'.", actualNameSpaces.contains(requiredNameSpace));
            }
        }
        if (notAllowedNameSpaces!=null) {
            log.debug("notAllowedNameSpaces: " + Arrays.toString(notAllowedNameSpaces.toArray()));
            for (final String notAllowedNameSpace : notAllowedNameSpaces) {
                assertFalse("Authorized to unexpected name space '" + notAllowedNameSpace + "'.", actualNameSpaces.contains(notAllowedNameSpace));
            }
        }
    }
}