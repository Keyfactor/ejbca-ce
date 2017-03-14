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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectManagerTestSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
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
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class AddAdminCommandTest {

    private static final String TESTCLASS_NAME = AddAdminCommandTest.class.getSimpleName();

    private final AccessUserAspectManagerTestSessionRemote accessUserAspectManagerTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            AccessUserAspectManagerTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private static X509CA x509ca = null;

    private AddAdminCommand command = new AddAdminCommand();
    private int roleId = Role.ROLE_ID_UNASSIGNED;

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
        roleId = roleSession.persistRole(authenticationToken, new Role(null, TESTCLASS_NAME)).getRoleId();
    }
    
    @After
    public void teardown() throws Exception {
        AdminGroupData role = roleAccessSession.findRole(TESTCLASS_NAME);
        if (role != null) {
            roleManagementSession.remove(authenticationToken, role);
        }
        roleSession.deleteRoleIdempotent(authenticationToken, roleId);
    }

    @Test
    public void testAddAdminCommandLegacy() throws AuthorizationDeniedException {
        final String matchValue = TESTCLASS_NAME + " Legacy";
        String[] args = new String[] { TESTCLASS_NAME, x509ca.getName(), X500PrincipalAccessMatchValue.WITH_COMMONNAME.toString(),
                AccessMatchType.TYPE_EQUALCASEINS.toString(), matchValue };
        command.execute(args);
        AccessUserAspect result = accessUserAspectManagerTestSession.find(AccessUserAspectData.generatePrimaryKey(TESTCLASS_NAME, x509ca.getCAId(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, matchValue));
        assertNotNull("Admin was not added,", result);
        final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(authenticationToken, roleId);
        /*
        assertEquals(1, roleMembers.size());
        final RoleMember roleMember = roleMembers.get(0);
        assertEquals(x509ca.getCAId(), roleMember.getTokenIssuerId());
        assertEquals(X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), roleMember.getTokenMatchKey());
        assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
        assertEquals(matchValue, roleMember.getTokenMatchValue());
        */
    }

    @Test
    public void testAddAdminCommand() throws AuthorizationDeniedException {
        final String matchValue = TESTCLASS_NAME;
        String[] args = new String[] { TESTCLASS_NAME, "--caname", x509ca.getName(), "--with", X500PrincipalAccessMatchValue.WITH_COMMONNAME.toString(),
                "--value", matchValue };
        command.execute(args);
        AccessUserAspect result = accessUserAspectManagerTestSession.find(AccessUserAspectData.generatePrimaryKey(TESTCLASS_NAME, x509ca.getCAId(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, matchValue));
        assertNotNull("Admin was not added,", result);
        final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(authenticationToken, roleId);
        /*
        assertEquals(1, roleMembers.size());
        final RoleMember roleMember = roleMembers.get(0);
        assertEquals(x509ca.getCAId(), roleMember.getTokenIssuerId());
        assertEquals(X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), roleMember.getTokenMatchKey());
        assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
        assertEquals(matchValue, roleMember.getTokenMatchValue());
        */
    }
}
