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
package org.cesecore;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;

/**
 * Base class with two good methods that can be used from other tests that needs to set up access roles. This base class can initialize the role
 * system with a role that have access to creating other roles.
 * 
 * @version $Id$
 * 
 */
public abstract class RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(RoleUsingTestCase.class);
    private static final AuthenticationToken alwaysAllowAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RoleUsingTestCase"));

    private static String roleName;
    protected static TestX509CertificateAuthenticationToken roleMgmgToken;
    private static RoleInitializationSessionRemote roleInitializationSession;

    protected static RoleInitializationSessionRemote getRoleInitializationSession() {
        if (roleInitializationSession==null) {
            roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        }
        return roleInitializationSession;
    }

    
    public static void setUpAuthTokenAndRole(final String roleName) throws RoleExistsException, RoleNotFoundException {
        String commonName = RoleUsingTestCase.class.getCanonicalName();
        roleMgmgToken = getRoleInitializationSession().createAuthenticationTokenAndAssignToNewRole("C=SE,O=Test,CN=" + commonName, null, roleName,
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
        // Setup legacy authorization as well to support gradual conversions of core
        setUpAuthTokenAndRoleLegacy(roleName);
        log.debug("<setUpAuthTokenAndRole roleName="+roleName + " roleMgmgToken="+roleMgmgToken);
    }

    @Deprecated
    private static void setUpAuthTokenAndRoleLegacy(String roleName) throws RoleExistsException, RoleNotFoundException {
        RoleUsingTestCase.roleName = roleName;       
        X509Certificate cert = (X509Certificate) roleMgmgToken.getCredentials().iterator().next();
        // Initialize the role mgmt system with this role that is allowed to edit roles, i.e. needs access to /
        final RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        if (roleAccessSessionRemote.findRole(roleName) == null) {
            final RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
            try {
                roleInitSession.initializeAccessWithCert(alwaysAllowAdmin, roleName, cert);
            } catch (AuthorizationDeniedException e) {
                // NOPMD This can't happen
            }
        }
    }

    public static void tearDownRemoveRole() throws RoleNotFoundException, AuthorizationDeniedException {
        log.debug(">tearDownRemoveRole roleMgmgToken="+roleMgmgToken);
        getRoleInitializationSession().removeAllAuthenticationTokensRoles(roleMgmgToken);
        // Tear down legacy authorization as well to support gradual conversions of core
        tearDownRemoveRoleLegacy();
    }

    @Deprecated
    private static void tearDownRemoveRoleLegacy() throws RoleNotFoundException, AuthorizationDeniedException {
        final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        final RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        if (roleAccessSessionRemote.findRole(roleName) != null) {
            roleManagementSession.remove(alwaysAllowAdmin, roleName);
        }
    }
    
    protected static TestX509CertificateAuthenticationToken createAuthenticationToken(String issuerDn) {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(issuerDn);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        principals.add(p);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return (TestX509CertificateAuthenticationToken) authenticationProvider.authenticate(subject);
    }
    
}
