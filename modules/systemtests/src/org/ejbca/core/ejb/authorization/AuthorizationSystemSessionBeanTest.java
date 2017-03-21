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
package org.ejbca.core.ejb.authorization;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * Test of AuthorizationSystemSessionBean functionality.
 * 
 * @version $Id$
 */
public class AuthorizationSystemSessionBeanTest {

    private static final Logger log = Logger.getLogger(AuthorizationSystemSessionBeanTest.class);

    private AuthorizationSystemSessionRemote authorizationSystemSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class);
    private RoleInitializationSessionRemote roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    @Test
    public void testAccessSets() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException, AuthenticationFailedException {
        log.trace(">testAccessSets");
        TestX509CertificateAuthenticationToken authenticationToken = null;
        try {
            final String roleName = "TestAccessSet";
            authenticationToken = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole("CN="+roleName, null, roleName,
                    Arrays.asList(StandardRules.CAFUNCTIONALITY.resource(), StandardRules.SYSTEMFUNCTIONALITY.resource()),
                    Arrays.asList(StandardRules.VIEWROLES.resource(), StandardRules.EDITROLES.resource()));
            // Now get an AccessSet and perform some testing on it
            final AccessSet accessSet = authorizationSystemSession.getAccessSetForAuthToken(authenticationToken);
            log.debug("Now dumping the allowed resources in the AccessSet:");
            accessSet.dumpRules();
            assertFalse("Should not have / access", accessSet.isAuthorized(StandardRules.ROLE_ROOT.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.CAFUNCTIONALITY.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.SYSTEMFUNCTIONALITY.resource()));
            assertFalse(accessSet.isAuthorized(StandardRules.VIEWROLES.resource()));
            assertFalse(accessSet.isAuthorized(StandardRules.EDITROLES.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.CAADD.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.CAEDIT.resource()));
            // Behaviors change after EJBCA 6.8.0, used to allow non-existing resources using recursive rule
            assertFalse(accessSet.isAuthorized(StandardRules.CAFUNCTIONALITY.resource()+"/unexistent"));
            assertTrue(accessSet.isAuthorized(StandardRules.SYSTEMCONFIGURATION_VIEW.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.CAFUNCTIONALITY.resource(), StandardRules.SYSTEMFUNCTIONALITY.resource()));
            assertTrue(accessSet.isAuthorized(StandardRules.CAADD.resource(), StandardRules.CAEDIT.resource()));
            assertFalse(accessSet.isAuthorized(StandardRules.CAADD.resource(), StandardRules.CAEDIT.resource(), StandardRules.VIEWROLES.resource()));
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationToken);
            log.trace("<testAccessSets");
        }
    }

}
