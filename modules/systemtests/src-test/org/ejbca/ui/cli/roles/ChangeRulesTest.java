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
package org.ejbca.ui.cli.roles;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * This class contains tests that involve rule changes from the CLI
 * 
 * @version $Id$
 *
 */
public class ChangeRulesTest {

    private static final String ROLENAME = "ChangeRulesTest";
    
    private RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    
    private AuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ChangeRulesTest"));
    private ChangeRuleCommand command = new ChangeRuleCommand();
    private int roleId = Role.ROLE_ID_UNASSIGNED;
    
    @Before
    public void setUp() throws Exception {
        final Role role = roleSession.persistRole(internalToken, new Role(null, ROLENAME));
        roleId = role.getRoleId();
    }
    
    @After
    public void tearDown() throws Exception {
        roleSession.deleteRoleIdempotent(internalToken, roleId);
    }
    
    /** Tests adding a legacy rule (such as /ca), just to make sure that rule changes work at all. */
    @Test
    public void testAddLegacyRule() throws AuthorizationDeniedException {
        final String accessRuleName = "/ca";
        command.execute(new String[]{ ROLENAME, accessRuleName, "ACCEPT", "-R"});
        final Role modifiedRole = roleSession.getRole(internalToken, null, ROLENAME);
        final String resource = AccessRulesHelper.normalizeResource(accessRuleName);
        assertNotNull("Rule " + resource + " was not added to role via CLI", modifiedRole.getAccessRules().get(resource));
        assertTrue("Rule " + resource + " was not added to role via CLI", modifiedRole.getAccessRules().get(resource).booleanValue());
    }
    
    /**
     * This is a regression test written for ECA-2427, when we discovered that access rules created in CESECORE
     * couldn't be added via the CLI.  
     */
    @Test
    public void testAddCesecoreRule() throws AuthorizationDeniedException {      
        final String accessRuleName = "/secureaudit";
        command.execute(new String[]{ ROLENAME, accessRuleName, "ACCEPT", "-R"});
        final Role modifiedRole = roleSession.getRole(internalToken, null, ROLENAME);
        final String resource = AccessRulesHelper.normalizeResource(accessRuleName);
        assertNotNull("Rule " + resource + " was not added to role via CLI", modifiedRole.getAccessRules().get(resource));
        assertTrue("Rule " + resource + " was not added to role via CLI", modifiedRole.getAccessRules().get(resource).booleanValue());
    }    
}
