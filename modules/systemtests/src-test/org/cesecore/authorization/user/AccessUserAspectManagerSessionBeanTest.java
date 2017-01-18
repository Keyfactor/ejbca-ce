/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.user;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * Functional tests for the AccessUserAspectManagerSessionBean class.
 * 
 * @version $Id$
 * 
 */
public class AccessUserAspectManagerSessionBeanTest {

    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private AccessUserAspectManagerTestSessionRemote accessUserAspectManagerSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            AccessUserAspectManagerTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);

    private AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AccessUserAspectManagerSessionBeanTest"));

    /**
     * Simple sanity test, meant to involve other session beans as little as possible.
     */
    @Test
    public void testCrudOperations() {

        final AdminGroupData role = new AdminGroupData(1337, "NerdHerder");
        final int caId = 4711;

        AccessUserAspectData result = null;
        Integer primaryKey = AccessUserAspectData.generatePrimaryKey(role.getRoleName(), caId, X500PrincipalAccessMatchValue.WITH_COUNTRY,
                AccessMatchType.TYPE_EQUALCASE, "SE");

        assertNull("accessUserAspectManagerSession.find did not return null for a non existing object.",
                accessUserAspectManagerSession.find(primaryKey));

        try {
            result = accessUserAspectManagerSession.create(role, caId, X500PrincipalAccessMatchValue.WITH_COUNTRY, AccessMatchType.TYPE_EQUALCASE,
                    "SE");
        } catch (AccessUserAspectExistsException e) {
            fail("You're probably running this test from a dirty database.");
        }
        try {
            assertNotNull("AccessUserAspect was not persisted sucessfully", accessUserAspectManagerSession.find(primaryKey));
        } finally {
            accessUserAspectManagerSession.remove(result);
            assertNull("AccessUserAspectManagerSessionRemote did not properly remove an object.", accessUserAspectManagerSession.find(primaryKey));
        }
    }

    /**
     * Verify that keys created with the old and new system can work in parallel
     */
    @Test
    public void testContainOldAndNewKeysInParallel() throws Exception {
        String roleName = "testContainOldAndNewKeysInParallel";
        String rule = "/" + roleName;
        String issuerDn1 = "CN=" + roleName + "1";
        String issuerDn2 = "CN=" + roleName + "2";
        int caId1 = issuerDn1.hashCode();
        int caId2 = issuerDn2.hashCode();
        @SuppressWarnings("deprecation")
        int oldStylePrimaryKey = AccessUserAspectData.generatePrimaryKeyOld(roleName, caId1,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE, roleName);
        AccessUserAspectData oldAspect = new AccessUserAspectData(roleName, caId1, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, roleName + "1");
        oldAspect.setPrimaryKey(oldStylePrimaryKey);
        AccessUserAspectData newAspect = new AccessUserAspectData(roleName, caId2, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, roleName + "2");
        try {
            AdminGroupData role = roleManagementSession.create(alwaysAllowAuthenticationToken, roleName);
            role = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, role, Arrays.asList(oldAspect, newAspect));
            AccessRuleData accessRule = new AccessRuleData(roleName, rule, AccessRuleState.RULE_ACCEPT, false);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, Arrays.asList(accessRule));
            X509CertificateAuthenticationToken authenticationTokenOld = (X509CertificateAuthenticationToken) createAuthenticationToken(issuerDn1);
            X509CertificateAuthenticationToken authenticationTokenNew = (X509CertificateAuthenticationToken) createAuthenticationToken(issuerDn2);
            assertTrue("Aspect created with the old style key wasn't authorized to rule.",
                    accessControlSession.isAuthorized(authenticationTokenOld, rule));
            assertTrue("Aspect created with the new style key wasn't authorized to rule.",
                    accessControlSession.isAuthorized(authenticationTokenNew, rule));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, roleName);
        }
    }

    /**
     * Verify that it shouldn't be possible to create an aspect with the same values as one created with the old primary key
     */
    @Test
    public void testCreateIdenticalAspects() throws Exception {
        String roleName = "testCreateIdenticalAspects";
        String rule = "/" + roleName;
        String issuerDn = "CN=" + roleName;
        int caId = issuerDn.hashCode();
        @SuppressWarnings("deprecation")
        int oldStylePrimaryKey = AccessUserAspectData.generatePrimaryKeyOld(roleName, caId,
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE, roleName);
        AccessUserAspectData oldAspect = new AccessUserAspectData(roleName, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, roleName);
        oldAspect.setPrimaryKey(oldStylePrimaryKey);
        AccessUserAspectData newAspect = new AccessUserAspectData(roleName, caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, roleName);
        try {
            AdminGroupData role = roleManagementSession.create(alwaysAllowAuthenticationToken, roleName);
            role = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, role, Arrays.asList(oldAspect));
            AccessRuleData accessRule = new AccessRuleData(roleName, rule, AccessRuleState.RULE_ACCEPT, false);
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, Arrays.asList(accessRule));
            //So far so good, now check that the new rule can be added in parallel           
            role = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, role, Arrays.asList(newAspect));
            //It should fail silently, so simply verify that the new value doesn't exist in the dababase.
            assertNotNull("New entry was not created.", accessUserAspectManagerSession.find(newAspect.getPrimaryKey()));
            assertNull("Old entry was not removed.", accessUserAspectManagerSession.find(newAspect.getLegacyPrimaryKey()));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, roleName);
            if (accessUserAspectManagerSession.find(newAspect.getPrimaryKey()) != null) {
                accessUserAspectManagerSession.remove(newAspect);
            }
            if (accessUserAspectManagerSession.find(oldAspect.getPrimaryKey()) != null) {
                accessUserAspectManagerSession.remove(oldAspect);
            }
        }

    }

    private static AuthenticationToken createAuthenticationToken(String issuerDn) {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(issuerDn);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        principals.add(p);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
                SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return authenticationProvider.authenticate(subject);
    }
}
