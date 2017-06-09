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

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
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
 */
public class AddRoleMemberCommandTest {

    private static final String TESTCLASS_NAME = AddRoleMemberCommandTest.class.getSimpleName();
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(TESTCLASS_NAME);

    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    private static X509CA x509ca = null;

    private final AddRoleMemberCommand command = new AddRoleMemberCommand();
    private int roleId = Role.ROLE_ID_UNASSIGNED;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (x509ca != null) {
            final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
            final int caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
            caSession.removeCA(authenticationToken, x509ca.getCAId());
        }
    }

    @Before
    public void setup() throws Exception {
        roleId = roleSession.persistRole(authenticationToken, new Role(null, TESTCLASS_NAME)).getRoleId();
    }
    
    @After
    public void teardown() throws Exception {
        roleSession.deleteRoleIdempotent(authenticationToken, roleId);
    }

    @Test
    public void testAddRoleMemberCommandLegacy() throws AuthorizationDeniedException {
        final String matchValue = TESTCLASS_NAME + " Legacy";
        String[] args = new String[] { TESTCLASS_NAME, x509ca.getName(), X500PrincipalAccessMatchValue.WITH_COMMONNAME.toString(),
                AccessMatchType.TYPE_EQUALCASEINS.toString(), matchValue };
        command.execute(args);
        final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(authenticationToken, roleId);
        assertEquals(1, roleMembers.size());
        final RoleMember roleMember = roleMembers.get(0);
        assertEquals(x509ca.getCAId(), roleMember.getTokenIssuerId());
        assertEquals(X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), roleMember.getTokenMatchKey());
        assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
        assertEquals(matchValue, roleMember.getTokenMatchValue());
    }

    @Test
    public void testAddRoleMemberCommand() throws AuthorizationDeniedException {
        final String matchValue = TESTCLASS_NAME;
        String[] args = new String[] { TESTCLASS_NAME, "--caname", x509ca.getName(), "--with", X500PrincipalAccessMatchValue.WITH_COMMONNAME.toString(),
                "--value", matchValue };
        command.execute(args);
        final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(authenticationToken, roleId);
        assertEquals(1, roleMembers.size());
        final RoleMember roleMember = roleMembers.get(0);
        assertEquals(x509ca.getCAId(), roleMember.getTokenIssuerId());
        assertEquals(X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), roleMember.getTokenMatchKey());
        assertEquals(AccessMatchType.TYPE_EQUALCASE.getNumericValue(), roleMember.getTokenMatchOperator());
        assertEquals(matchValue, roleMember.getTokenMatchValue());
    }
}
