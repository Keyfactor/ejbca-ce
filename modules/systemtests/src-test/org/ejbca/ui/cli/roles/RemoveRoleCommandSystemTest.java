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
import org.cesecore.dto.RoleDataDto;
import org.cesecore.dto.RoleDataDtoBuilder;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class RemoveRoleCommandSystemTest {

    private static final String TESTCLASS_NAME = RemoveRoleCommandSystemTest.class.getSimpleName();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RemoveRoleCommand command = new RemoveRoleCommand();

    @Before
    public void setup() throws Exception {
        final var role = new RoleDataDtoBuilder()
                .setName(TESTCLASS_NAME)
                .build();
        roleSession.persistRole(authenticationToken, role);
    }

    @After
    public void teardown() throws Exception {
        final RoleDataDto role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(authenticationToken, role.id());
        }
    }

    @Test
    public void testRemoveRole() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        final RoleDataDto role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        assertNull("Role was not removed,", role);
    }
}
