/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.roles;

import static org.junit.Assert.assertNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id: RemoveRoleCommandTest.java 18481 2014-02-10 16:08:27Z mikekushner $
 */
public class RemoveRoleCommandTest {

    private static final String TESTCLASS_NAME = RemoveRoleCommandTest.class.getSimpleName();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RemoveRoleCommand command = new RemoveRoleCommand();

    @Before
    public void setup() throws Exception {
        roleSession.persistRole(authenticationToken, new Role(null, TESTCLASS_NAME));
    }

    @After
    public void teardown() throws Exception {
        final Role role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(authenticationToken, role.getRoleId());
        }
    }

    @Test
    public void testRemoveRole() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        final Role role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        assertNull("Role was not removed,", role);
    }
}
