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
package org.cesecore.authorization.control;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionRemote;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
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

    private static final Logger log = Logger.getLogger(AccessControlSessionBeanTest.class);

    private AuthorizationSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSessionRemote.class);
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    //private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleMemberProxySessionRemote roleMemberProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AuthorizationSessionBeanTest"));

    @Test
    public void testIsAuthorizedAlwaysAllow() {
        authorizationSession.isAuthorizedNoLogging(alwaysAllowAuthenticationToken, "/a", "/b");
        authorizationSession.isAuthorized(alwaysAllowAuthenticationToken, "/a", "/b");
    }

    @Test
    public void testIsAuthorized() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
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
            accessRules.put("/decline/accept", Role.STATE_ALLOW);
            accessRules.put("/decline/decline", Role.STATE_DENY);
            final Role role = roleSession.persistRole(alwaysAllowAuthenticationToken, new Role(nameSpace, roleName, accessRules));

            final String commonName = roleName;
            final String subjectAndIssuerDn = "CN="+commonName;
            final int caId = subjectAndIssuerDn.hashCode();
            roleMemberProxySession.createOrEdit(new RoleMember(0, X500PrincipalAccessMatchValue.WITH_COMMONNAME, caId, commonName, role.getRoleId(), null, null));

            final AuthenticationToken authenticationToken = createAuthenticationToken("CN="+commonName);

            assertFalse(authorizationSession.isAuthorized(authenticationToken, StandardRules.ROLE_ROOT.resource()));
            /* Being able to do successful authorization checks for an X500Principal requires ECA-5653 (tokenIssuerId) to be implemented
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/accept"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/decline"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/notused"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/unexistent"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/accept"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/decline"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/notused"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/unexistent"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/accept/notused"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/decline/notused"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/notused/notused"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/accept/accept"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/accept/decline"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/accept/notused"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/accept/unexistent"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/decline/accept"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/decline/decline"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/decline/notused"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/decline/unexistent"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertTrue(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/decline", "/acceptRecursive/accept"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline"));
            assertFalse(authorizationSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline", "/acceptRecursive/unexistent"));
             */
        } finally {
            cleanUpRole(nameSpace, roleName);
        }
    }
    
    private void cleanUpRole(final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("cleanUpRole"));
        final Role role = roleSession.getRole(authenticationToken, nameSpace, roleName);
        if (role!=null) {
            final List<RoleMember> roleMembers = roleMemberProxySession.findRoleMemberByRoleId(role.getRoleId());
            for (final RoleMember roleMember : roleMembers) {
                roleMemberProxySession.remove(roleMember.getId());
            }
            try {
                roleSession.deleteRole(authenticationToken, role.getRoleId());
            } catch (RoleNotFoundException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private AuthenticationToken createAuthenticationToken(final String subjectAndIssuerDn) {
        final AuthenticationSubject authenticationSubject = new AuthenticationSubject(new HashSet<Principal>(Arrays.asList(new X500Principal(subjectAndIssuerDn))), null);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(
                SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return authenticationProvider.authenticate(authenticationSubject);
    }
}
