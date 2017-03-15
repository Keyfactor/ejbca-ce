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

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class RemoveAdminCommandTest {

    private final String ROLENAME = "AdminsRemoveAdminCommandTest";
    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken("AdminsRemoveAdminCommandTest");

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);

    private final RemoveAdminCommand command = new RemoveAdminCommand();
    private int roleId = Role.ROLE_ID_UNASSIGNED;

    @Before
    public void setUp() throws Exception {
        roleId = roleSession.persistRole(internalAdmin, new Role(null, ROLENAME)).getRoleId();
    }

    @After
    public void tearDown() throws Exception {
        roleSession.deleteRoleIdempotent(internalAdmin, roleId);
    }

    @Test
    public void testRemoveAccessUser() throws Exception {
        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        final CA testx509ca = CaTestUtils.createTestX509CA("CN=TestCA", null, false, keyusage);
        final int caId = testx509ca.getCAId();
        caSession.addCA(internalAdmin, testx509ca);
        try {
            final String matchValue = "foo";
            roleMemberSession.createOrEdit(internalAdmin, new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                    matchValue, roleId, null, null));
            String[] args = { ROLENAME, "TestCA", "WITH_COMMONNAME", "TYPE_EQUALCASE", "foo" };
            command.execute(args);
            final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(internalAdmin, roleId);
            assertEquals("RoleMember was not removed via CLI command", 0, roleMembers.size());
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
            caSession.removeCA(internalAdmin, caId);
        }
    }
}
