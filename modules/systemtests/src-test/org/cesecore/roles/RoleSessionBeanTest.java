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
import static org.junit.Assert.fail;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
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

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AuthorizationSessionBeanTest"));

    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final Role cleanUpRole = roleSession.getRole(alwaysAllowAuthenticationToken, nameSpace, roleName);
        if (cleanUpRole!=null) {
            roleSession.deleteRoleIdempotent(alwaysAllowAuthenticationToken, cleanUpRole.getRoleId(), false);
        }
    }
    
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
        try {
            roleSession.deleteRole(alwaysAllowAuthenticationToken, createdRole.getRoleId(), false);
        } catch (RoleNotFoundException e) {
            fail("Unable to delete the role created by this test.");
        }
    }

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
}
