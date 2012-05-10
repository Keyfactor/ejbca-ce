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
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
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

    private static final AuthenticationToken alwaysAllowAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RoleUsingTestCase"));

    private String roleName;
    protected AuthenticationToken roleMgmgToken;

    public void setUpAuthTokenAndRole(String roleName) throws RoleExistsException, RoleNotFoundException {
        this.roleName = roleName;       
        String commonname = this.getClass().getCanonicalName();
        roleMgmgToken = createAuthenticationToken("C=SE,O=Test,CN=" + commonname);
        X509Certificate cert = (X509Certificate) roleMgmgToken.getCredentials().iterator().next();
        // Initialize the role mgmt system with this role that is allowed to edit roles
        final RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        if (roleAccessSessionRemote.findRole(roleName) == null) {
            final RoleInitializationSessionRemote roleInitSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
            roleInitSession.initializeAccessWithCert(roleMgmgToken, roleName, cert);
        }
    }

    public void tearDownRemoveRole() throws RoleNotFoundException, AuthorizationDeniedException {
        final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
        final RoleAccessSessionRemote roleAccessSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        if (roleAccessSessionRemote.findRole(roleName) != null) {
            roleManagementSession.remove(alwaysAllowAdmin, roleName);
        }
    }
    
    protected AuthenticationToken createAuthenticationToken(String issuerDn) {
        Set<Principal> principals = new HashSet<Principal>();
        X500Principal p = new X500Principal(issuerDn);
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        principals.add(p);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return authenticationProvider.authenticate(subject);
    }
    
}
