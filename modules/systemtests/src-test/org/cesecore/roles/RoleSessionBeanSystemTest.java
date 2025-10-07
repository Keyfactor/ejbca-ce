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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test of RoleSessionBean.
 * 
 * @version $Id$
 */
public class RoleSessionBeanSystemTest {
    
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleInitializationSessionRemote roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final Logger log = Logger.getLogger(RoleSessionBeanSystemTest.class);

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(RoleSessionBeanSystemTest.class.getSimpleName());

    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final RoleDataDto role = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace, roleName);
        if (role != null) {
            roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, role.id());
        }
    }

    private void cleanUpRoles() throws AuthorizationDeniedException {
        cleanUpRole(null, "RoleSessionBeanSystemTest.testCrud");
        cleanUpRole("companyx", "RoleSessionBeanSystemTest.testCrud (renamed)");
        cleanUpRole(null, "RoleSessionBeanSystemTest.testConflict");
        cleanUpRole(null, "RoleSessionBeanSystemTest.testRename");
        cleanUpRole(null, "RoleSessionBeanSystemTest.testRenamedRole");
        cleanUpRole(null, "RoleSessionBeanSystemTest.testAddRemoveAccess");
        cleanUpRole(null, "testIsAuthorizedToDeleteOwnRoleMember");
        cleanUpRole(null, "testIsAuthorizedToDeleteOwnRoleMember2");
    }

    @Before
    public void setUp() throws Exception {
        cleanUpRoles();
    }

    @After
    public void tearDown() throws Exception {
        cleanUpRoles();
    }

    /**
     * Basic sanity test for role operations
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testCrud() throws RoleExistsException, AuthorizationDeniedException {
        // Create
        final RoleDataDto role = new RoleDataDtoBuilder()
                .setName("RoleSessionBeanSystemTest.testCrud")
                .setAccessRules(Map.of("/", RoleDataDto.STATE_ALLOW))
                .build();
        final RoleDataDto createdRole = roleSession.persistRole(alwaysAllowAuthenticationToken, role);
        assertFalse("createdRole is expected to have an ID", createdRole.isIdUnassigned());
        assertEquals("createdRole has wrong namespace", role.nameSpace(), createdRole.nameSpace());
        assertEquals("createdRole has wrong name", role.name(), createdRole.name());
        assertEquals("createdRole has wrong access rules", role.accessRules(), createdRole.accessRules());
        // Read
        final RoleDataDto fetchedRole = roleSession.getRole(alwaysAllowAuthenticationToken, createdRole.id());
        String message = "Expected:\n" + createdRole + "\nActual:\n" + fetchedRole;
        assertEquals(message, createdRole, fetchedRole);

        // Update (including renaming and change of namespace)
        Map<String, Boolean> accessRules = new HashMap<>(fetchedRole.accessRules());
        accessRules.put("/a/b", RoleDataDto.STATE_DENY);
        RoleDataDto modifiedRole = new RoleDataDtoBuilder(fetchedRole)
                .setAccessRules(accessRules)
                .setName(fetchedRole.name() + " (renamed)")
                .setNameSpace("companyx")
                .build();
        final RoleDataDto updatedRole = roleSession.persistRole(alwaysAllowAuthenticationToken, modifiedRole);
        assertEquals("Wrong RoleDataDto", modifiedRole, updatedRole);

        // Delete
        assertTrue("Unable to delete the role created by this test.", roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, createdRole.id()));
    }

    private RoleDataDto getRoleData(final String name) {
        return new RoleDataDtoBuilder()
                .setName(name)
                .build();
    }

    /**
     * Expects exception thrown while adding two roles with identical namespace and role name combination
     * @throws RoleExistsException
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testNameConflict() throws RoleExistsException, AuthorizationDeniedException {
        final String name = "RoleSessionBeanSystemTest.testConflict";
        // Create
        final RoleDataDto role1 = getRoleData(name).withAccessRules(Map.of("/", RoleDataDto.STATE_ALLOW));
        final RoleDataDto persisted = roleSession.persistRole(alwaysAllowAuthenticationToken, role1);
        assertNotNull("Failed to get the role that was just added", roleSession.getRole(alwaysAllowAuthenticationToken, persisted.nameSpace(), persisted.name()));
        final RoleDataDto role2 = getRoleData(name).withAccessRules(Map.of("/", RoleDataDto.STATE_ALLOW));
        try {
            roleSession.persistRole(alwaysAllowAuthenticationToken, role2);
            fail("Should not have been able to create 2 roles with the same nameSpace + roleName combination.");
        } catch (RoleExistsException e) {
        }
    }
    
    /**
     * Attempts renaming a role and assumes the role remains persisted with the same roleId 
     * but with a new name
     * @throws AuthorizationDeniedException
     * @throws RoleExistsException
     */
    @Test
    public void testRenameRole() throws AuthorizationDeniedException, RoleExistsException {
        final String defaultName = "RoleSessionBeanSystemTest.testRename";
        final String newName = "RoleSessionBeanSystemTest.testRenamedRole";
        //Set up role
        RoleDataDto roleToRename = getRoleData(defaultName);
        RoleDataDto persistedRole = roleSession.persistRole(alwaysAllowAuthenticationToken, roleToRename);
        //Rename
        RoleDataDto renamedRole = persistedRole.withName(newName);
        roleSession.persistRole(alwaysAllowAuthenticationToken, renamedRole);

        //Get persisted role and verify id + name change
        RoleDataDto retrievedRole = roleSession.getRole(alwaysAllowAuthenticationToken, persistedRole.id());
        assertEquals("Wrong ID", persistedRole.id(), retrievedRole.id());
        assertEquals("Wrong name", newName, retrievedRole.name());
    }
    
    /**
     * Tests basic behavior while editing access rules for roles.
     * @throws AuthorizationDeniedException
     */
    @Test
    public void testAddAndRemoveAccessRulesToRole() throws AuthorizationDeniedException, RoleExistsException {
        //Create
        final String ROLE_NAME = "RoleSessionBeanSystemTest.testAddRemoveAccess";
        final String RULE1 = "/future/rama";
        final String RULE2 = "/future/world";

        final RoleDataDto role = getRoleData(ROLE_NAME).withAccessRules(Map.of(RULE1, RoleDataDto.STATE_ALLOW));
        RoleDataDto persisted = roleSession.persistRole(alwaysAllowAuthenticationToken, role);

        // Check the returned role
        assertEquals(1, persisted.accessRules().size());
        assertEquals(RoleDataDto.STATE_ALLOW, persisted.accessRules().get(AccessRulesHelper.normalizeResource(RULE1)));

        // Do the same check for a role retrieved from the database,
        RoleDataDto foundRole = roleSession.getRole(alwaysAllowAuthenticationToken, persisted.id());
        assertEquals(1, foundRole.accessRules().size());
        assertEquals(RoleDataDto.STATE_ALLOW, foundRole.accessRules().get(AccessRulesHelper.normalizeResource(RULE1)));

        // Add another rule
        Map<String, Boolean> extendedAccessRules = new HashMap<>(persisted.accessRules());
        extendedAccessRules.put(RULE2, RoleDataDto.STATE_ALLOW);
        RoleDataDto updatedRoleData = roleSession.persistRole(alwaysAllowAuthenticationToken, persisted.withAccessRules(extendedAccessRules));

        // Check that both rules (and only those two) are there.
        final Map<String, Boolean> retrievedRules = roleSession.getRole(alwaysAllowAuthenticationToken, persisted.id()).accessRules();
        assertEquals(2, retrievedRules.size());
        assertEquals(RoleDataDto.STATE_ALLOW, retrievedRules.get(AccessRulesHelper.normalizeResource(RULE1)));
        assertEquals(RoleDataDto.STATE_ALLOW, retrievedRules.get(AccessRulesHelper.normalizeResource(RULE2)));

        // Remove one of rules
        final Map<String, Boolean> reducedAccessRules = new HashMap<>(retrievedRules);
        reducedAccessRules.remove(AccessRulesHelper.normalizeResource(RULE1));
        final RoleDataDto roleDataWithReducedAccessRules = roleSession.persistRole(alwaysAllowAuthenticationToken, updatedRoleData.withAccessRules(reducedAccessRules));

        // Verify database commit
        assertEquals(1, roleDataWithReducedAccessRules.accessRules().size());
        assertEquals(RoleDataDto.STATE_ALLOW, roleDataWithReducedAccessRules.accessRules().get(AccessRulesHelper.normalizeResource(RULE2)));

        // Verify that futureRama has been removed entirely
        assertNull(roleDataWithReducedAccessRules.accessRules().get(AccessRulesHelper.normalizeResource(RULE1)));
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
        final String unAuthRoleName = "UnAuthRole";
        final String authDN = "CN=AccessTest";
        RoleDataDto authRole = getRoleData(authRoleName);
        RoleDataDto unAuthRole = getRoleData(unAuthRoleName);
        cleanUpRole(null, authRoleName);
        cleanUpRole(null, unAuthRoleName);
        List<String> accessRules = Arrays.asList(StandardRules.EDITROLES.toString());
        
        //Create tokens representing access rules of created roles
        AuthenticationToken authToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, authRole.name(), accessRules, null);
        AuthenticationToken unAuthToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(authDN, null, unAuthRoleName, null, accessRules);
        
        authRole = roleSession.getRole(authToken, null, authRoleName);
        unAuthRole = roleSession.getRole(unAuthToken, null, unAuthRoleName);
        assertNotNull(authRole);
        assertNotNull(unAuthRole);
        
        //Test edit. AuthorizationDeniedException is expected
        try {
            roleSession.deleteRoleIdempotent(unAuthToken, authRole.id());
            fail("Was able to edit role without proper authorization");
        } finally {
            cleanUpRole(null, authRoleName);
            cleanUpRole(null, unAuthRoleName);
        }
    }

    /** Verify that an administrator cannot edit a RoleDataDto that is providing all its access */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToNotEditOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToNotEditOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        RoleDataDto role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            Map<String, Boolean> accessRules = Map.of(StandardRules.CAACCESS.resource(), RoleDataDto.STATE_ALLOW);
            role = role.withAccessRules(accessRules);
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
        RoleDataDto role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        try {
            try {
                roleSession.persistRole(authenticationToken, role.withNameSpace("PrimeKey"));
            } catch (AuthorizationDeniedException e) { } // NOPMD expected
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator cannot remove the RoleDataDto that is providing all its access */
    @Test(expected = AuthorizationDeniedException.class)
    public void testIsAuthorizedToNotDeleteOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToNotDeleteOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        final RoleDataDto role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            roleSession.deleteRoleIdempotent(authenticationToken, role.id());
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
        final RoleDataDto role;
        try {
            role = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
        } catch (AuthorizationDeniedException e) {
            fail(e.getMessage());
            return;
        }
        try {
            final RoleMember roleMember = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role.id()).get(0);
            roleMemberSession.remove(authenticationToken, roleMember.getId());
            fail("Was able to lower own access.");
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }

    private RoleDataDto getRoleData(final String name, final String allowed) {
        return new RoleDataDtoBuilder()
                .setName(name)
                .setAccessRules(Map.of(allowed, RoleDataDto.STATE_ALLOW))
                .build();
    }

    /** Verify that an administrator can remove the RoleDataDto that is providing redundant access */
    public void testIsAuthorizedToDeleteOwnRole() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToDeleteOwnRole";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            final RoleDataDto role1 = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
            final List<RoleMember> roleMembers1 = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role1.id());
            final RoleDataDto role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, getRoleData(TESTNAME+"2", StandardRules.CAACCESS.resource()));
            final RoleMember roleMember2 = new RoleMember(roleMembers1.get(0));
            roleMember2.setId(RoleMember.ROLE_MEMBER_ID_UNASSIGNED);
            roleMember2.setRoleId(role2.id());
            roleMemberSession.persist(alwaysAllowAuthenticationToken, roleMember2);
            try {
                roleSession.deleteRoleIdempotent(authenticationToken, role1.id());
            } catch (AuthorizationDeniedException e) {
                fail("Unable to delete RoleDataDto that provides redundant access: " +e.getMessage());
            }
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
        }
    }
    
    /** Verify that an administrator can remove the RoleDataDto that is providing redundant access */
    public void testIsAuthorizedToDeleteOwnRoleMember() throws RoleExistsException, AuthorizationDeniedException {
        final String TESTNAME = "testIsAuthorizedToDeleteOwnRoleMember";
        final TestX509CertificateAuthenticationToken authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+TESTNAME, null, TESTNAME,
                Arrays.asList(StandardRules.CAACCESS.resource()), null);
        try {
            final RoleDataDto role1 = roleSession.getRole(alwaysAllowAuthenticationToken, null, TESTNAME);
            final List<RoleMember> roleMembers1 = roleMemberSession.getRoleMembersByRoleId(alwaysAllowAuthenticationToken, role1.id());
            final RoleDataDto role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, getRoleData(TESTNAME+"2", StandardRules.CAACCESS.resource()));
            final RoleMember roleMember2 = new RoleMember(roleMembers1.get(0));
            roleMember2.setId(RoleMember.ROLE_MEMBER_ID_UNASSIGNED);
            roleMember2.setRoleId(role2.id());
            roleMemberSession.persist(alwaysAllowAuthenticationToken, roleMember2);
            try {
                roleMemberSession.remove(authenticationToken, roleMembers1.get(0).getId());
            } catch (AuthorizationDeniedException e) {
                fail("Unable to delete RoleMember that provides redundant access: " +e.getMessage());
            } finally {
                roleSession.deleteRoleIdempotent(authenticationToken, role1.id());
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
            RoleDataDto strongRole = roleSession.getRole(alwaysAllowAuthenticationToken, null, strongAdminRoleName);
            RoleDataDto weakRole = roleSession.getRole(alwaysAllowAuthenticationToken, null, weakAdminRoleName);
            List<RoleDataDto> strongAuthorizedRoles = roleSession.getAuthorizedRoles(strongToken);
            List<RoleDataDto> weakAuthorizedRoles = roleSession.getAuthorizedRoles(weakToken);
            for (RoleDataDto role : weakAuthorizedRoles) {
                log.info(role.name());
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
            final RoleDataDto role = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace1, roleName1).withName(roleName2);
            final RoleDataDto roleUpdate1 = roleSession.persistRole(alwaysAllowAuthenticationToken, role);
            assertEquals(role.id(), roleUpdate1.id());
            assertNull(roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace1, roleName1));
            final RoleDataDto roleUpdate2 = roleSession.persistRole(alwaysAllowAuthenticationToken, roleUpdate1.withNameSpace(nameSpace2));
            assertEquals(role.id(), roleUpdate2.id());
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
            // Authentication token matching RoleMember that belongs to RoleDataDto with empty name space should see all namespaces
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace4),
                    Arrays.asList(nameSpace3), true);
            // Add authenticationToken1 matched by CN to RoleDataDto 2 (with nameSpace2)
            addRoleMemberToRole(nameSpace2, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2), null, false);
            // And again, add authenticationToken1 matched by CN to RoleDataDto 3 (with nameSpace3)
            RoleMember roleMember = addRoleMemberToRole(nameSpace3, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2, nameSpace3), null, false);
            // Sanity check that adding authenticationToken1 did not grant more access to the other authenticationTokens
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace4),
                    Arrays.asList(nameSpace3), true);
            // Remove authenticationToken1 matched by CN from RoleDataDto 3 (with nameSpace3) and expect that this namespace is no longer available
            roleMemberSession.remove(alwaysAllowAuthenticationToken, roleMember.getId());
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1, nameSpace2), null, false);
            // Grant additional access to authenticationToken4 and expect that namespace3 will now also be visible
            final RoleDataDto role4 = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4, commonRoleName);
            Map<String, Boolean> accessRules = new HashMap<>(role4.accessRules());
            accessRules.put(StandardRules.ROLE_ROOT.resource(), RoleDataDto.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4.withAccessRules(accessRules));
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1, nameSpace2, nameSpace3, nameSpace4), null, true);
            // Revoke additional access from authenticationToken4 and expect that namespace3 will no longer be visible
            final RoleDataDto role4b = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4, commonRoleName);
            accessRules = new HashMap<>();
            accessRules.put(StandardRules.CAACCESS.resource(), RoleDataDto.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4b.withAccessRules(accessRules));
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
            // Authentication token matching RoleMember that belongs to RoleDataDto with empty name space should see all namespaces
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace3b, nameSpace1a, nameSpace2a, nameSpace3a), true);
            // Add authenticationToken1 matched by CN to RoleDataDto 2 (with nameSpace2)
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace2b, nameSpace2a);
            addRoleMemberToRole(nameSpace2a, commonRoleName, subjectDn1);
            reassignRoleToDifferentNameSpace(commonRoleName, nameSpace2a, nameSpace2b);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b),
                    Arrays.asList(nameSpace1a, nameSpace2a), false);
            // And again, add authenticationToken1 matched by CN to RoleDataDto 3 (with nameSpace3)
            RoleMember roleMember = addRoleMemberToRole(nameSpace3b, commonRoleName, subjectDn1);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace3b),
                    Arrays.asList(nameSpace1a, nameSpace2a, nameSpace3a), false);
            // Sanity check that adding authenticationToken1 did not grant more access to the other authenticationTokens
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken2), Arrays.asList(nameSpace2b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken3), Arrays.asList(nameSpace3b), null, false);
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace4a),
                    Arrays.asList(nameSpace3b), true);
            // Remove authenticationToken1 matched by CN from RoleDataDto 3 (with nameSpace3) and expect that this namespace is no longer available
            roleMemberSession.remove(alwaysAllowAuthenticationToken, roleMember.getId());
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken1), Arrays.asList(nameSpace1b, nameSpace2b),
                    Arrays.asList(nameSpace1a, nameSpace2a), false);
            // Grant additional access to authenticationToken4 and expect that namespace3 will now also be visible
            final RoleDataDto role4 = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4a, commonRoleName);
            Map<String, Boolean> accessRules = new HashMap<>(role4.accessRules());
            accessRules.put(StandardRules.ROLE_ROOT.resource(), RoleDataDto.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4.withAccessRules(accessRules));
            assertNameSpacePresence(roleSession.getAuthorizedNamespaces(authenticationToken4), Arrays.asList(nameSpace1b, nameSpace2b, nameSpace3b, nameSpace4a),
                    Arrays.asList(nameSpace1a, nameSpace2a, nameSpace3a), true);
            // Revoke additional access from authenticationToken4 and expect that namespace3 will no longer be visible
            final RoleDataDto role4b = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace4a, commonRoleName);
            accessRules = new HashMap<>();
            accessRules.put(StandardRules.CAACCESS.resource(), RoleDataDto.STATE_ALLOW);
            roleSession.persistRole(alwaysAllowAuthenticationToken, role4b.withAccessRules(accessRules));
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
    
    /** Move a RoleDataDto from one name space to another */
    private void reassignRoleToDifferentNameSpace(final String roleName, final String oldNameSpace, final String newNameSpace) throws AuthorizationDeniedException, RoleExistsException {
        final RoleDataDto role = roleSession.getRole(alwaysAllowAuthenticationToken, oldNameSpace, roleName);
        roleSession.persistRole(alwaysAllowAuthenticationToken, role.withNameSpace(newNameSpace));
    }

    /** Add self signed certificate match to a role identified by name and return the persisted RoleMember */
    private RoleMember addRoleMemberToRole(final String nameSpace, final String roleName, final String subjectDn) throws AuthorizationDeniedException {
        final RoleDataDto role = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace, roleName);
        return roleMemberSession.persist(alwaysAllowAuthenticationToken, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                subjectDn.hashCode(), RoleMember.NO_PROVIDER, X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue(),
                AccessMatchType.TYPE_EQUALCASE.getNumericValue(), subjectDn, role.id(), null));
        
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