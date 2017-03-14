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
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectManagerTestSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.Role;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class RemoveAdminCommandTest {

    private static final String ROLENAME = "AdminsRemoveAdminCommandTest";

    private AccessUserAspectManagerTestSessionRemote accessUserAspectManagerTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessUserAspectManagerTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AdminsRemoveAdminCommandTest"));

    private RemoveAdminCommand command = new RemoveAdminCommand();
    private int roleId = Role.ROLE_ID_UNASSIGNED;

    @Before
    public void setUp() throws Exception {
        tearDown();
        roleManagementSession.create(internalAdmin, ROLENAME);
        roleId = roleSession.persistRole(internalAdmin, new Role(null, ROLENAME)).getRoleId();
    }

    @After
    public void tearDown() throws Exception {
        if (roleAccessSessionRemote.findRole(ROLENAME) != null) {
            roleManagementSession.remove(internalAdmin, ROLENAME);
        }
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
            AdminGroupData role = roleAccessSessionRemote.findRole(ROLENAME);
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(new AccessUserAspectData(ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                    matchValue));
            roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
            String[] args = { ROLENAME, "TestCA", "WITH_COMMONNAME", "TYPE_EQUALCASE", "foo" };
            command.execute(args);
            assertNull("User aspect was not removed via CLI command", accessUserAspectManagerTestSession.find(AccessUserAspectData.generatePrimaryKey(
                    ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, matchValue)));
            final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(internalAdmin, roleId);
            //assertEquals("RoleMember was not removed via CLI command", 0, roleMembers.size());
        } finally {
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
            caSession.removeCA(internalAdmin, caId);
        }
    }
}
