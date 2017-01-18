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
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class AddRoleCommandTest {

    private final String TESTCLASS_NAME = AddRoleCommandTest.class.getSimpleName();

    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private AddRoleCommand command = new AddRoleCommand();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);

    @After
    public void teardown() throws Exception {
        AdminGroupData role = roleAccessSession.findRole(TESTCLASS_NAME);
        if (role != null) {
            roleManagementSession.remove(authenticationToken, role);
        }
    }

    @Test
    public void testAddRoleCommand() {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        assertNotNull("Role was not added.", roleAccessSession.findRole(TESTCLASS_NAME));
    }

}
