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
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.Role;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id: RemoveRoleCommandTest.java 18481 2014-02-10 16:08:27Z mikekushner $
 *
 */
public class RemoveRoleCommandTest {

    private static final String TESTCLASS_NAME = RemoveRoleCommandTest.class.getSimpleName();

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private static X509CA x509ca = null;

    private RemoveRoleCommand command = new RemoveRoleCommand();

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (x509ca != null) {
            final int caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
            caSession.removeCA(authenticationToken, x509ca.getCAId());
        }
    }

    @Before
    public void setup() throws Exception {
        roleManagementSession.create(authenticationToken, TESTCLASS_NAME);
        roleSession.persistRole(authenticationToken, new Role(null, TESTCLASS_NAME));
    }

    @After
    public void teardown() throws Exception {
        AdminGroupData adminGroupData = roleAccessSession.findRole(TESTCLASS_NAME);
        if (adminGroupData != null) {
            roleManagementSession.remove(authenticationToken, adminGroupData);
        }
        final Role role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(authenticationToken, role.getRoleId());
        }
    }

    @Test
    public void testRemoveRole() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        AdminGroupData adminGroupData = roleAccessSession.findRole(TESTCLASS_NAME);
        assertNull("Role was not removed,", adminGroupData);
        final Role role = roleSession.getRole(authenticationToken, null, TESTCLASS_NAME);
        //assertNull("Role was not removed,", role);
    }
}
