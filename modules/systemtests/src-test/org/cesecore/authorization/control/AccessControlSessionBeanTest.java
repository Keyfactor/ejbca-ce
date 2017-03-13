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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionRemote;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestX509CertificateAuthenticationToken;
import org.cesecore.mock.authentication.tokens.UsernameAccessMatchValue;
import org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleInitializationSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Functional tests for AccessControlSessionBean
 * 
 * @version $Id$
 */
public class AccessControlSessionBeanTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(AccessControlSessionBeanTest.class);
    
    private AuthorizationSessionRemote authorizationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSessionRemote.class);
    private AuthorizationSystemSessionRemote authorizationSystemSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class);
    //private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    //private RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private RoleInitializationSessionRemote roleInitializationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleInitializationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    private AccessControlSessionRemote accessControlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(AccessControlSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
  
    private final AuthenticationToken alwaysAllowAuthenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AccessControlSessionBeanTest"));
    
    @Before
    public void setUp() throws Exception {    	
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("AccessControlSessionTest");
    }

    @After
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
    	tearDownRemoveRole();
    }

    @Test
    public void testIsAuthorized() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        // Let's set up a role and a nice resource tree to play with.
        final String roleName = "NerfHerder";
        try {
            AdminGroupData nerfHerder = roleManagementSession.create(alwaysAllowAuthenticationToken, roleName);      
            String issuerDn = "CN="+roleName;
            X509CertificateAuthenticationToken authenticationToken = (X509CertificateAuthenticationToken) createAuthenticationToken(issuerDn);
            int caId = issuerDn.hashCode();
           
            List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
            accessUsers.add(new AccessUserAspectData(nerfHerder.getRoleName(), caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                    AccessMatchType.TYPE_EQUALCASE, roleName));
            
            roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, nerfHerder, accessUsers);          
            
            List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();       
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_NOTUSED, false));            
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive", AccessRuleState.RULE_ACCEPT, true));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/accept", AccessRuleState.RULE_ACCEPT, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/decline", AccessRuleState.RULE_DECLINE, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/accept", AccessRuleState.RULE_ACCEPT, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/decline", AccessRuleState.RULE_DECLINE, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/accept/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/notused/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/acceptRecursive/decline/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/accept/accept", AccessRuleState.RULE_ACCEPT, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/accept/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/accept/decline", AccessRuleState.RULE_DECLINE, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/decline/accept", AccessRuleState.RULE_ACCEPT, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/decline/notused", AccessRuleState.RULE_NOTUSED, false));
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/decline/decline", AccessRuleState.RULE_DECLINE, false));    
            roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, nerfHerder, accessRules);            

            assertFalse(accessControlSession.isAuthorized(authenticationToken, StandardRules.ROLE_ROOT.resource()));
           
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive"));            
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/accept"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/decline"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/notused"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/unexistent"));
            
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/accept"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/decline"));
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/notused"));
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/unexistent"));
            
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/accept/notused"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/decline/notused"));
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/notused/notused"));
            
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/accept/accept"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/accept/decline"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/accept/notused"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/accept/unexistent"));
          
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/decline/accept"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/decline/decline"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/decline/notused"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/decline/unexistent"));
      
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertTrue(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/notused", "/acceptRecursive/unexistent"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/decline", "/acceptRecursive/accept"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline"));
            assertFalse(accessControlSession.isAuthorized(authenticationToken, "/acceptRecursive/accept", "/acceptRecursive/decline", "/acceptRecursive/unexistent"));
        } finally {
            roleManagementSession.remove(alwaysAllowAuthenticationToken, roleName);
        }
    }

    @Test
    public void testNestedIsAuthorized() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException, AuthenticationFailedException {
        TestX509CertificateAuthenticationToken authenticationTokenClient = null;
        TestX509CertificateAuthenticationToken authenticationTokenRaServer = null;
        TestX509CertificateAuthenticationToken authenticationTokenProxyServer = null;
        try {
            // Let's set up a role and a nice resource tree to play with.
            final String roleNameClients = "Dragon";
            final String roleNameViaRaServer = "LonelyMountainRaServer";
            final String roleNameViaProxyServer = "MiddleEarthProxyServer";
            final String issuerDnClients = "CN="+roleNameClients;
            final String issuerViaRaServer = "CN="+roleNameViaRaServer;
            final String issuerViaProxyServer = "CN="+roleNameViaProxyServer;
            authenticationTokenClient = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(issuerDnClients, null, roleNameClients,
                    Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
            authenticationTokenRaServer = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(issuerViaRaServer, null, roleNameViaRaServer,
                    Arrays.asList(StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), StandardRules.CREATECRL.resource()), null);
            authenticationTokenProxyServer = roleInitializationSession.createAuthenticationTokenAndAssignToNewRole(issuerViaProxyServer, null, roleNameViaProxyServer,
                    Arrays.asList(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAFUNCTIONALITY.resource()), null);
            // Direct access by almighty client should allow anything
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.ROLE_ROOT.resource()));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.CREATECRL.resource()));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            final AccessSet accessSet1 = authorizationSystemSession.getAccessSetForAuthToken(authenticationTokenClient);
            accessSet1.dumpRules();
            assertTrue(accessSet1.isAuthorized(AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(accessSet1.isAuthorized(StandardRules.CREATECRL.resource()));
            assertTrue(accessSet1.isAuthorized(StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            assertTrue(accessSet1.isAuthorized(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            
            // Direct access by RA server
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.ROLE_ROOT.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.CREATECRL.resource()));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            final AccessSet accessSet2 = authorizationSystemSession.getAccessSetForAuthToken(authenticationTokenRaServer);
            assertFalse(accessSet2.isAuthorized(StandardRules.ROLE_ROOT.resource()));
            assertFalse(accessSet2.isAuthorized(AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(accessSet2.isAuthorized(StandardRules.CREATECRL.resource()));
            assertTrue(accessSet2.isAuthorized(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            
            // Direct access by Proxy server
            assertFalse(authorizationSession.isAuthorized(authenticationTokenProxyServer, StandardRules.ROLE_ROOT.resource()));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenProxyServer, AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenProxyServer, StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            final AccessSet accessSet3 = authorizationSystemSession.getAccessSetForAuthToken(authenticationTokenProxyServer);
            assertFalse(accessSet3.isAuthorized(StandardRules.ROLE_ROOT.resource()));
            assertTrue(accessSet3.isAuthorized(AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(accessSet3.isAuthorized(StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            
            // Access by RA server via Proxy server
            authenticationTokenRaServer.appendNestedAuthenticationToken(authenticationTokenProxyServer);
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.ROLE_ROOT.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.CREATECRL.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenRaServer, StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            final AccessSet accessSet4 = authorizationSystemSession.getAccessSetForAuthToken(authenticationTokenRaServer);
            assertFalse(accessSet4.isAuthorized(StandardRules.ROLE_ROOT.resource()));
            assertFalse(accessSet4.isAuthorized(AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(accessSet4.isAuthorized(StandardRules.CREATECRL.resource()));
            assertFalse(accessSet4.isAuthorized(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            assertFalse(accessSet4.isAuthorized(StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            
            // Access by Client via RA server via Proxy server
            authenticationTokenClient.appendNestedAuthenticationToken(authenticationTokenRaServer);
            assertFalse(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.ROLE_ROOT.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenClient, AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.CREATECRL.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            assertFalse(authorizationSession.isAuthorized(authenticationTokenClient, StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            final AccessSet accessSet5 = authorizationSystemSession.getAccessSetForAuthToken(authenticationTokenClient);
            assertFalse(accessSet5.isAuthorized(StandardRules.ROLE_ROOT.resource()));
            assertFalse(accessSet5.isAuthorized(AccessRulesConstants.ROLE_ADMINISTRATOR));
            assertTrue(accessSet5.isAuthorized(StandardRules.CREATECRL.resource()));
            assertFalse(accessSet5.isAuthorized(StandardRules.CERTIFICATEPROFILEEDIT.resource()));
            assertFalse(accessSet5.isAuthorized(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()));
            
        } finally {
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationTokenClient);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationTokenRaServer);
            roleInitializationSession.removeAllAuthenticationTokensRoles(authenticationTokenProxyServer);
        }
    }

    /**
     * This test tests that authentication tokens only match the types aspects they were created from.
     * @throws AuthorizationDeniedException 
     * @throws RoleExistsException 
     * @throws RoleNotFoundException 
     */
    @Test
    public void testDifferentationBetweenDifferentAuthenticationTokens() throws RoleExistsException, AuthorizationDeniedException, RoleNotFoundException {
        //Create a role    
        final String roleName = "MasterController";
        final String resourceName = "/Encom"; 
        final String tronDn = "CN=Tron";
        final String flynnDn = "CN=Flynn";
        AdminGroupData role = roleAccessSession.findRole(roleName);
        if (role == null) {
            role = roleManagementSession.create(alwaysAllowAuthenticationToken, roleName);
        }
        try {
            //Give the role a ClI-based aspect and an X509-based aspect
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            AccessUserAspectData tron = new AccessUserAspectData(roleName, tronDn.hashCode(), UsernameAccessMatchValue.USERNAME, AccessMatchType.TYPE_EQUALCASE, "Tron");
            AccessUserAspectData flynn = new AccessUserAspectData(roleName, flynnDn.hashCode(), X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, "Flynn");
            subjects.add(tron);
            subjects.add(flynn);
            role = roleManagementSession.addSubjectsToRole(alwaysAllowAuthenticationToken, role, subjects);
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            accessRules.add(new AccessRuleData(roleName, resourceName, AccessRuleState.RULE_ACCEPT, false));
            role = roleManagementSession.addAccessRulesToRole(alwaysAllowAuthenticationToken, role, accessRules);
            
            //Let's produce two valid tokens.          
            AuthenticationToken validUsernameToken = new UsernameBasedAuthenticationToken(new UsernamePrincipal("Tron"));
            //Make sure that the two valid usernames work.
            if(!accessControlSession.isAuthorizedNoLogging(validUsernameToken, resourceName)) {
                throw new RuntimeException("Test can't continue, valid token was not authorized.");
            }
            AuthenticationToken validX509Token = createAuthenticationToken(flynnDn);
            if(!accessControlSession.isAuthorizedNoLogging(validX509Token, resourceName)) {
                throw new RuntimeException("Test can't continue, valid token was not authorized.");
            }
            // Now, create a X509 token pretending to be a UsernameBasedAuthenticationToken using the same DN.             
            AuthenticationToken invalidX509Token = createAuthenticationToken(tronDn); 
            // Make sure that this token would have matched if not for the token type check
            assertFalse("Invalid X509 token should not have been able to authorize", accessControlSession.isAuthorizedNoLogging(invalidX509Token, resourceName));
        } finally {
            try {
                roleManagementSession.remove(alwaysAllowAuthenticationToken, role);
            } catch (RoleNotFoundException e) {
                //ignore
            }
        }
    }
    
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
