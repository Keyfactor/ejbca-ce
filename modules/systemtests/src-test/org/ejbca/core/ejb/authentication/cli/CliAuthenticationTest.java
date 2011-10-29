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
package org.ejbca.core.ejb.authentication.cli;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.RemoveException;
import javax.persistence.PersistenceException;

import org.cesecore.authentication.AuthenticationSessionRemote;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.CliAuthenticationToken;
import org.ejbca.ui.cli.CliUserAccessMatchValue;
import org.ejbca.util.crypto.CryptoTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests in this class test aspect of CLI authentication.
 * 
 * @version $Id$
 * 
 */
public class CliAuthenticationTest {

    private static final String CLI_TEST_ROLENAME = "CLI_TEST_ROLENAME";

    private final AuthenticationSessionRemote authenticationSession = JndiHelper.getRemoteSession(AuthenticationSessionRemote.class);
    private final AccessControlSessionRemote accessControlSession = JndiHelper.getRemoteSession(AccessControlSessionRemote.class);
    private final CliAuthenticationProviderRemote cliAuthenticationProvider = JndiHelper.getRemoteSession(CliAuthenticationProviderRemote.class);
    private final ConfigurationSessionRemote configurationSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private final UserAdminSessionRemote userAdminSessionRemote = JndiHelper.getRemoteSession(UserAdminSessionRemote.class);

    private CliAuthenticationTestHelperSessionRemote cliAuthenticationTestHelperSession = JndiHelper
            .getRemoteSession(CliAuthenticationTestHelperSessionRemote.class);

    private final TestAlwaysAllowLocalAuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CliAuthenticationProviderRemote.class.getSimpleName()));

    @Before
    public void setUp() throws Exception {
        RoleData role = roleManagementSession.create(internalToken, CLI_TEST_ROLENAME);
        List<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(CLI_TEST_ROLENAME, 0, CliUserAccessMatchValue.USERNAME,
                AccessMatchType.TYPE_EQUALCASE, CliAuthenticationTestHelperSessionRemote.USERNAME);
        subjects.add(defaultCliUserAspect);
        roleManagementSession.addSubjectsToRole(internalToken, role, subjects);

        AccessRuleData rule = new AccessRuleData(CLI_TEST_ROLENAME, "/", AccessRuleState.RULE_ACCEPT, true);
        List<AccessRuleData> newrules = new ArrayList<AccessRuleData>();
        newrules.add(rule);
        roleManagementSession.addAccessRulesToRole(internalToken, role, newrules);
    }

    @After
    public void tearDown() throws Exception {
        userAdminSessionRemote.deleteUser(internalToken, CliAuthenticationTestHelperSessionRemote.USERNAME);
        roleManagementSession.remove(internalToken, CLI_TEST_ROLENAME);
        configurationSession.restoreConfiguration();
    }

    @Test
    public void testInstallCliAuthenticationWithBCrypt() throws PersistenceException, CADoesntExistsException, AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException, RemoveException {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) authenticationSession.authenticate(subject, cliAuthenticationProvider);
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword(CliAuthenticationTestHelperSessionRemote.PASSWORD);
        assertTrue(accessControlSession.isAuthorized(authenticationToken, "/"));
    }

    @Test
    public void testInstallCliAuthenticationWithOldHash() {
        configurationSession.updateProperty("ejbca.passwordlogrounds", "0");
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) authenticationSession.authenticate(subject, cliAuthenticationProvider);
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword(CliAuthenticationTestHelperSessionRemote.PASSWORD);
        assertFalse("Old-style hash value was not used (BCrypt prefix detected).", authenticationToken.getSha1Hash().startsWith(CryptoTools.BCRYPT_PREFIX));
        assertTrue(accessControlSession.isAuthorized(authenticationToken, "/"));
    }

}
