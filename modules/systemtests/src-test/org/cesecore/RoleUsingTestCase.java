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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderSessionRemote;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;

/**
 * Base class with two good methods that can be used from other tests that needs to set up access roles. This base class can initialize the role
 * system with a role that have access to creating other roles.
 * 
 * @version $Id$
 */
public abstract class RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(RoleUsingTestCase.class);
    private static RoleInitializationSessionRemote roleInitializationSession;

    protected static TestX509CertificateAuthenticationToken roleMgmgToken;

    protected static RoleInitializationSessionRemote getRoleInitializationSession() {
        if (roleInitializationSession==null) {
            roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        }
        return roleInitializationSession;
    }

    public static void setUpAuthTokenAndRole(final String roleName) throws RoleExistsException, RoleNotFoundException {
        setUpAuthTokenAndRole(null, roleName, null, null);
    }

    public static void setUpAuthTokenAndRole(final String nameSpace, final String roleName, final List<String> resourcesAllowed, final List<String> resourcesDenied) throws RoleExistsException, RoleNotFoundException {
        final String commonName = RoleUsingTestCase.class.getCanonicalName();
        roleMgmgToken = getRoleInitializationSession().createAuthenticationTokenAndAssignToNewRole("C=SE,O=Test,CN=" + commonName, nameSpace, roleName,
                resourcesAllowed, resourcesDenied);
        log.debug("<setUpAuthTokenAndRole roleName="+roleName + " roleMgmgToken="+roleMgmgToken);
    }

    public static void tearDownRemoveRole() throws RoleNotFoundException, AuthorizationDeniedException {
        log.debug(">tearDownRemoveRole roleMgmgToken="+roleMgmgToken);
        getRoleInitializationSession().removeAllAuthenticationTokensRoles(roleMgmgToken);
    }

    protected static TestX509CertificateAuthenticationToken createAuthenticationToken(String issuerDn) {
        final AuthenticationSubject subject = new AuthenticationSubject(new HashSet<Principal>(Arrays.asList(new X500Principal(issuerDn))), null);
        final SimpleAuthenticationProviderSessionRemote authenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(SimpleAuthenticationProviderSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        return (TestX509CertificateAuthenticationToken) authenticationProvider.authenticate(subject);
    }    
}
