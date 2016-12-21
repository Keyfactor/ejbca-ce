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
package org.ejbca.core.ejb.authentication.cli;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.RemoveException;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.util.crypto.CryptoTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests in this class test aspect of CLI authentication.
 * 
 * Note that this test does not actually involve the CLI, it just tests the authentication 
 * that the CLI should use.
 * 
 * @version $Id$
 * 
 */
public class CliAuthenticationTest {

    private static final String CLI_TEST_ROLENAME = "CLI_TEST_ROLENAME";

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private final AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private final CliAuthenticationProviderSessionRemote cliAuthenticationProvider = EjbRemoteHelper.INSTANCE.getRemoteSession(CliAuthenticationProviderSessionRemote.class);
    private final ConfigurationSessionRemote configurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private final SecurityEventsAuditorSessionRemote securityEventsAuditorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);    

    private CliAuthenticationTestHelperSessionRemote cliAuthenticationTestHelperSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CliAuthenticationTestHelperSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final TestAlwaysAllowLocalAuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            CliAuthenticationProviderSessionRemote.class.getSimpleName()));
  

    @Before
    public void setUp() throws Exception {        
        RoleData role = roleAccessSession.findRole(CLI_TEST_ROLENAME);
        if(role == null) {
            role = roleManagementSession.create(internalToken, CLI_TEST_ROLENAME);
        }
        List<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(CLI_TEST_ROLENAME, 0, CliUserAccessMatchValue.USERNAME,
                AccessMatchType.TYPE_EQUALCASE, CliAuthenticationTestHelperSessionRemote.USERNAME);
        subjects.add(defaultCliUserAspect);
        roleManagementSession.addSubjectsToRole(internalToken, role, subjects);

        AccessRuleData rule = new AccessRuleData(CLI_TEST_ROLENAME, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
        List<AccessRuleData> newrules = new ArrayList<AccessRuleData>();
        newrules.add(rule);
        roleManagementSession.addAccessRulesToRole(internalToken, role, newrules);       
    }

    @After
    public void tearDown() throws Exception {
        try {
            endEntityManagementSession.deleteUser(internalToken, CliAuthenticationTestHelperSessionRemote.USERNAME);
        } catch (NoSuchEndEntityException e) {
            // NOPMD
        }
        try {
            roleManagementSession.remove(internalToken, CLI_TEST_ROLENAME);
        } catch(RoleNotFoundException e) {
         // NOPMD
        }
        configurationSession.restoreConfiguration();
    }

    @Test
    public void testInstallCliAuthenticationWithBCrypt() throws EndEntityExistsException, CADoesntExistsException, AuthorizationDeniedException,
            EndEntityProfileValidationException, WaitingForApprovalException, EjbcaException, RemoveException {
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken =  (CliAuthenticationToken) cliAuthenticationProvider.authenticate(subject);
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword(CliAuthenticationTestHelperSessionRemote.PASSWORD);
        assertTrue(accessControlSession.isAuthorized(authenticationToken, StandardRules.ROLE_ROOT.resource()));
    }

    @Test
    public void testInstallCliAuthenticationWithOldHash() {        
        configurationSession.updateProperty("ejbca.passwordlogrounds", "0");
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) cliAuthenticationProvider.authenticate(subject);
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword(CliAuthenticationTestHelperSessionRemote.PASSWORD);
        assertFalse("Old-style hash value was not used (BCrypt prefix detected).", authenticationToken.getSha1Hash().startsWith(CryptoTools.BCRYPT_PREFIX));
        assertTrue(accessControlSession.isAuthorized(authenticationToken, StandardRules.ROLE_ROOT.resource()));
    }
    
    /**
     * This test tests CLI Authentication failure as per the Common Criteria standard:
     * 
     *    FIA_UAU.1 Timing of authentication
     *    Unsuccessful use of the authentication mechanism
     *    
     *    FIA_UID.1 Timing of identification
     *    Unsuccessful use of the user identification mechanism, including the
     *    user identity provided 
     * @throws AuthorizationDeniedException 
     */
    @Test
    public void testAuthenticationFailureDueToNonExistingUser() throws AuthorizationDeniedException {
        final String expectedMessage = intres.getLocalizedMessage("authentication.failed.cli.usernotfound", CliAuthenticationTestHelperSessionRemote.USERNAME );
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) cliAuthenticationProvider.authenticate(subject);
        assertNull("Authentication token was returned for nonexistant user", authenticationToken);
        //Examine the last log entry
        for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
            Map<String, Object> details = list.get(list.size()-1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");           
            assertEquals("Incorrect log message was produced.", expectedMessage, msg);
        }
    }
    
    @Test 
    public void testAuthenticationFailureDueToIncorrectPassword() throws AuthorizationDeniedException {
        final String expectedMessage = intres.getLocalizedMessage("authentication.failed", "" );
        cliAuthenticationTestHelperSession.createUser(CliAuthenticationTestHelperSessionRemote.USERNAME, CliAuthenticationTestHelperSessionRemote.PASSWORD);
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(CliAuthenticationTestHelperSessionRemote.USERNAME));
        AuthenticationSubject subject = new AuthenticationSubject(principals, null);
        CliAuthenticationToken authenticationToken =  (CliAuthenticationToken) cliAuthenticationProvider.authenticate(subject);
        // Set hashed value anew in order to send back
        authenticationToken.setSha1HashFromCleartextPassword("monkeys");
        assertFalse("Authentication token was returned for incorrect password", accessControlSession.isAuthorized(authenticationToken, StandardRules.ROLE_ROOT.resource()));
        //Examine the last log entry
        for (final String logDeviceId : securityEventsAuditorSession.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditorSession.selectAuditLogs(internalToken, 0, 0,
                    QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderAsc("sequenceNumber")), logDeviceId);
            Map<String, Object> details = list.get(list.size()-1).getMapAdditionalDetails();
            String msg = (String) details.get("msg");           
            final String expectedRegexp = expectedMessage + ".*";
            assertTrue("Incorrect log message was produced. (Was: <" + msg + ">. Expected to match: <" +  expectedRegexp +">", msg.matches(expectedRegexp));
        }
    }

}
