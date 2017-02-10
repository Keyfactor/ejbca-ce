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
package org.cesecore.authorization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.NestableAuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberProxySessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * System test of AuthorizationSessionBean.
 * 
 * @version $Id$
' */
public class AuthorizationSessionBeanTest {

    //private static final Logger log = Logger.getLogger(AuthorizationSessionBeanTest.class);

    private AuthorizationSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSessionRemote.class);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private RoleMemberProxySessionRemote roleMemberProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AuthorizationSessionBeanTest"));

    @Test
    public void testIsAuthorizedAlwaysAllow() {
        assertTrue(authorizationSession.isAuthorizedNoLogging(alwaysAllowAuthenticationToken, "/a", "/b"));
        assertTrue(authorizationSession.isAuthorized(alwaysAllowAuthenticationToken, "/a", "/b"));
    }

    @Test
    public void testIsAuthorizedSingleRole() throws RoleExistsException, AuthorizationDeniedException {
        // Let's set up a role and a nice resource tree to play with.
        final String nameSpace = null;
        final String roleName = "Role testIsAuthorized";
        try {
            final HashMap<String,Boolean> accessRules = new HashMap<>();
            accessRules.put("/accept", Role.STATE_ALLOW);
            accessRules.put("/decline", Role.STATE_DENY);
            accessRules.put("/acceptRecursive", Role.STATE_ALLOW);
            accessRules.put("/acceptRecursive/accept", Role.STATE_ALLOW);
            accessRules.put("/acceptRecursive/decline", Role.STATE_DENY);
            accessRules.put("/accept/accept", Role.STATE_ALLOW);
            accessRules.put("/accept/decline", Role.STATE_DENY);
            accessRules.put("/somerule/accept", Role.STATE_ALLOW);
            accessRules.put("/somerule/decline", Role.STATE_DENY);
            final Role role = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName, accessRules));
            final String commonName = roleName;
            final String subjectAndIssuerDn = "CN="+commonName;
            final int caId = subjectAndIssuerDn.hashCode();
            final int roleMemberId = roleMemberProxySession.createOrEdit(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), commonName, role.getRoleId(), null, null));
            assertEquals(caId, roleMemberProxySession.findRoleMember(roleMemberId).getTokenIssuerId());
            final AuthenticationToken authenticationToken = createAuthenticationToken("CN="+commonName);
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource()));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/accept"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/decline"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/accept"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/decline"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/accept/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/decline/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/notused/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/accept/accept"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/accept/decline"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/accept/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/accept/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/accept"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/decline"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/decline", "/acceptRecursive/accept"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline", "/acceptRecursive/unexistent"));
        } finally {
            cleanUpRole(nameSpace, roleName);
        }
    }

    @Test
    public void testIsAuthorizedBelongToMoreThanOneGroup() throws RoleExistsException, AuthorizationDeniedException {
        final String nameSpace = null;
        final String commonName = "Role testIsAuthorized";
        final String roleName1 = commonName + "1";
        final String roleName2 = commonName + "2";
        try {
            final HashMap<String,Boolean> accessRules1 = new HashMap<>();
            accessRules1.put("/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/allowInBoth", Role.STATE_ALLOW);
            accessRules1.put("/allowInBoth/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/allowInBoth/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/allowInFirst/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/allowInFirst/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/somerule/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/somerule/denyInFirst", Role.STATE_DENY);
            final Role role1 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName1, accessRules1));
            final HashMap<String,Boolean> accessRules2 = new HashMap<>();
            accessRules2.put("/allowInBoth", Role.STATE_ALLOW);
            accessRules2.put("/allowInBoth/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInBoth/denyInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInFirst/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInFirst/denyInFirst", Role.STATE_ALLOW);
            accessRules2.put("/somerule/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/somerule/denyInFirst", Role.STATE_DENY);
            final Role role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName2, accessRules2));
            final String subjectAndIssuerDn = "CN="+commonName;
            final int caId = subjectAndIssuerDn.hashCode();
            final int roleMemberId1 = roleMemberProxySession.createOrEdit(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), commonName, role1.getRoleId(), null, null));
            assertEquals(caId, roleMemberProxySession.findRoleMember(roleMemberId1).getTokenIssuerId());
            final int roleMemberId2 = roleMemberProxySession.createOrEdit(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), commonName, role2.getRoleId(), null, null));
            assertEquals(caId, roleMemberProxySession.findRoleMember(roleMemberId2).getTokenIssuerId());
            assertFalse(roleMemberId1==roleMemberId2);
            final AuthenticationToken authenticationToken = createAuthenticationToken("CN="+commonName);
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource()));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/accept"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/denyInFirst"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused", "/allowInBoth/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst", "/allowInBoth/notused", "/allowInBoth/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst", "/allowInBoth/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst", "/allowInBoth/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/acceptInOne", "/allowInBoth/denyInFirst", "/allowInBoth/unexistent"));
        } finally {
            cleanUpRole(nameSpace, roleName1);
            cleanUpRole(nameSpace, roleName2);
        }
    }

    @Test
    public void testIsAuthorizedNestedAuthenticationToken() throws RoleExistsException, AuthorizationDeniedException {
        final String nameSpace = null;
        final String commonName1 = "Role testIsAuthorized 1";
        final String commonName2 = "Role testIsAuthorized 2";
        final String roleName1 = commonName1;
        final String roleName2 = commonName2;
        try {
            final HashMap<String,Boolean> accessRules1 = new HashMap<>();
            accessRules1.put("/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/allowInBoth", Role.STATE_ALLOW);
            accessRules1.put("/allowInBoth/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/allowInBoth/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/allowInFirst/allowInFirst", Role.STATE_ALLOW);
            accessRules1.put("/allowInFirst/denyInFirst", Role.STATE_DENY);
            accessRules1.put("/somerule/accept", Role.STATE_ALLOW);
            accessRules1.put("/somerule/denyInFirst", Role.STATE_DENY);
            final Role role1 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName1, accessRules1));
            final HashMap<String,Boolean> accessRules2 = new HashMap<>();
            accessRules2.put("/allowInBoth", Role.STATE_ALLOW);
            accessRules2.put("/allowInBoth/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInBoth/denyInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInFirst/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/allowInFirst/denyInFirst", Role.STATE_ALLOW);
            accessRules2.put("/somerule/allowInFirst", Role.STATE_DENY);
            accessRules2.put("/somerule/denyInFirst", Role.STATE_DENY);
            final Role role2 = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName2, accessRules2));
            assertFalse(role1.getRoleId()==role2.getRoleId());
            final String subjectAndIssuerDn = "CN="+commonName1;
            final int caId = subjectAndIssuerDn.hashCode();
            final int roleMemberId1 = roleMemberProxySession.createOrEdit(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), commonName1, role1.getRoleId(), null, null));
            assertEquals(caId, roleMemberProxySession.findRoleMember(roleMemberId1).getTokenIssuerId());
            final String subjectAndIssuerDn2 = "CN="+commonName2;
            final int caId2 = subjectAndIssuerDn2.hashCode();
            final int roleMemberId2 = roleMemberProxySession.createOrEdit(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                    caId2, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(),
                    AccessMatchType.TYPE_EQUALCASE.getNumericValue(), commonName2, role2.getRoleId(), null, null));
            assertEquals(caId2, roleMemberProxySession.findRoleMember(roleMemberId2).getTokenIssuerId());
            assertFalse(roleMemberId1==roleMemberId2);
            final AuthenticationToken authenticationToken = createAuthenticationToken("CN="+commonName1);
            final AuthenticationToken nestedAuthenticationToken = createAuthenticationToken("CN="+commonName2);
            ((NestableAuthenticationToken)authenticationToken).appendNestedAuthenticationToken((NestableAuthenticationToken) nestedAuthenticationToken);
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource()));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst/notused"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInFirst/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/notused"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/somerule/unexistent"));
            assertTrue( authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/notused", "/allowInBoth/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst", "/allowInBoth/notused", "/allowInBoth/unexistent"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/denyInFirst", "/allowInBoth/allowInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst", "/allowInBoth/denyInFirst"));
            assertFalse(authorizationSession.isAuthorizedNoLogging(authenticationToken, "/allowInBoth/allowInFirst", "/allowInBoth/denyInFirst", "/allowInBoth/unexistent"));
        } finally {
            cleanUpRole(nameSpace, roleName1);
            cleanUpRole(nameSpace, roleName2);
        }
    }
    
    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("cleanUpRole"));
        final Role role = roleSession.getRole(authenticationToken, nameSpace, roleName);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(authenticationToken, role.getRoleId());
        }
    }

    private AuthenticationToken createAuthenticationToken(final String subjectAndIssuerDn) {
        final AuthenticationSubject authenticationSubject = new AuthenticationSubject(new HashSet<Principal>(Arrays.asList(new X500Principal(subjectAndIssuerDn))), null);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
                SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return authenticationProvider.authenticate(authenticationSubject);
    }
}
