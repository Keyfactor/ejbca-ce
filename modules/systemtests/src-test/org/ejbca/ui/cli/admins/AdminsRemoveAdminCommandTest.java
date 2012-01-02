/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.admins;

import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Collection;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectManagerTestSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class AdminsRemoveAdminCommandTest {

    private static final String ROLENAME = "AdminsRemoveAdminCommandTest";

    private AccessUserAspectManagerTestSessionRemote accessUserAspectManagerTestSession = JndiHelper
            .getRemoteSession(AccessUserAspectManagerTestSessionRemote.class);
    private CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AdminsRemoveAdminCommandTest"));

    private AdminsRemoveAdminCommand command = new AdminsRemoveAdminCommand();
    private RoleData role;

    @Before
    public void setUp() throws Exception {
        if ((role = roleAccessSessionRemote.findRole(ROLENAME)) == null) {
            role = roleManagementSession.create(internalAdmin, ROLENAME);
        }
    }

    @After
    public void tearDown() throws Exception {
        if (roleAccessSessionRemote.findRole(ROLENAME) != null) {
            roleManagementSession.remove(internalAdmin, ROLENAME);
        }
    }

    @Test
    public void testRemoveAccessUser() throws CADoesntExistsException, AuthorizationDeniedException, RoleNotFoundException,
            ErrorAdminCommandException {
        Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        final int caId = caSession.getCAInfo(internalAdmin, "AdminCA1").getCAId();
        final String matchValue = "foo";
        subjects.add(new AccessUserAspectData(ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                matchValue));
        roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
        String[] args = { "removeadmin", ROLENAME, "AdminCA1", "WITH_COMMONNAME", "TYPE_EQUALCASE", "foo" };
        command.execute(args);
        assertNull("User aspect was not removed via CLI command", accessUserAspectManagerTestSession.find(AccessUserAspectData.generatePrimaryKey(
                ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, matchValue)));
    }

}
