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
package org.ejbca.ui.cli.roles;

import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectManagerTestSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
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
    private RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("AdminsRemoveAdminCommandTest"));

    private RemoveAdminCommand command = new RemoveAdminCommand();
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
    public void testRemoveAccessUser() throws Exception {
        
        int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        CA testx509ca = CaTestUtils.createTestX509CA("CN=TestCA", null, false, keyusage);
        final int caId = testx509ca.getCAId();
        caSession.addCA(internalAdmin, testx509ca);
        
        Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        final String matchValue = "foo";
        subjects.add(new AccessUserAspectData(ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                matchValue));
        roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
        String[] args = { ROLENAME, "TestCA", "WITH_COMMONNAME", "TYPE_EQUALCASE", "foo" };
        command.execute(args);
        assertNull("User aspect was not removed via CLI command", accessUserAspectManagerTestSession.find(AccessUserAspectData.generatePrimaryKey(
                ROLENAME, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, matchValue)));
        
        CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        caSession.removeCA(internalAdmin, caId);
        
    }

}
