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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Functional tests for AccessControlSessionBean
 * 
 * Based on cesecore version:
 *      AccessControlSessionBeanTest.java 506 2011-03-10 12:46:42Z tomas
 * 
 * @version $Id: AccessControlSessionBeanTest.java 12186 2011-07-27 09:33:06Z mikekushner $
 * 
 */
public class AccessControlSessionBeanTest extends RoleUsingTestCase {

    private AccessControlSessionRemote accessControlSession = JndiHelper.getRemoteSession(AccessControlSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    @Before
    public void setUp() throws RoleExistsException, RoleNotFoundException {    	
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
        RoleData nerfHerder = roleManagementSession.create(roleMgmgToken, "NerfHerder");

        X509Certificate[] certificateArray = new X509Certificate[1]; 
        certificateArray = roleMgmgToken.getCredentials().toArray(certificateArray);
        
        int caId = CertTools.getIssuerDN(certificateArray[0]).hashCode();
        
        try {

            List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
            accessUsers.add(new AccessUserAspectData(nerfHerder.getRoleName(), caId, AccessMatchValue.WITH_COUNTRY, AccessMatchType.TYPE_EQUALCASE, "SE"));
            roleManagementSession.addSubjectsToRole(roleMgmgToken, nerfHerder, accessUsers);
            
            List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            
            accessRules.add(new AccessRuleData(nerfHerder.getRoleName(), "/", AccessRuleState.RULE_NOTUSED, false));            
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
            roleManagementSession.addAccessRulesToRole(roleMgmgToken, nerfHerder, accessRules);            

            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/"));
           
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive"));            
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/accept"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/decline"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/notused"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/unexistent"));
            
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/accept"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/decline"));
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/notused"));
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/unexistent"));
            
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/accept/notused"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/decline/notused"));
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/acceptRecursive/notused/notused"));
            
            assertTrue(accessControlSession.isAuthorized(roleMgmgToken, "/accept/accept"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/accept/decline"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/accept/notused"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/accept/unexistent"));
          
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/decline/accept"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/decline/decline"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/decline/notused"));
            assertFalse(accessControlSession.isAuthorized(roleMgmgToken, "/decline/unexistent"));
            
            
        } finally {
            roleManagementSession.remove(roleMgmgToken, nerfHerder);
        }

    }

}
