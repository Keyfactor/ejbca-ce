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

import static org.junit.Assert.assertNotNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Test;

/**
 * @version $Id$
 */
public class AddRoleCommandTest {

    private final String TESTCLASS_NAME = AddRoleCommandTest.class.getSimpleName();
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);
    private final AddRoleCommand command = new AddRoleCommand();

    @After
    public void teardown() throws Exception {
        final Role oldRole = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        if (oldRole!=null) {
            roleSession.deleteRoleIdempotent(authenticationToken, oldRole.getRoleId());
        }
    }

    @Test
    public void testAddRoleCommand() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        final Role addedRole = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        assertNotNull("Role was not added.", addedRole);
    }
}
