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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
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
    
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    
    private AuthenticationToken internalToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ChangeRulesTest"));
    private ChangeRuleCommand command;
    
    @Before
    public void setUp() throws Exception {
        roleManagementSession.create(internalToken, ROLENAME);
        command = new ChangeRuleCommand();
    }
    
    @After
    public void tearDown() throws Exception {
        if(roleAccessSession.findRole(ROLENAME) != null) {
            roleManagementSession.remove(internalToken, ROLENAME);
        }
    }
    
    /**
     * Tests adding a legacy rule (such as /ca), just to make sure that rule changes
     * work at all.
     */
    @Test
    public void testAddLegacyRule() {
        final String accessRuleName = "/ca";
        command.execute(new String[]{ ROLENAME, accessRuleName, "ACCEPT", "-R"});
        RoleData role = roleAccessSession.findRole(ROLENAME);
        AccessRuleData rule = role.getAccessRules().get((AccessRuleData.generatePrimaryKey(ROLENAME, accessRuleName)));
        assertNotNull("Rule " + accessRuleName + " was not added to role via CLI", rule);
    }
    
    /**
     * This is a regression test written for ECA-2427, when we discovered that access rules created in CESECORE
     * couldn't be added via the CLI. 
     * 
     */
    @Test
    public void testAddCesecoreRule() {      
            final String accessRuleName = "/secureaudit";
            command.execute(new String[]{ ROLENAME, accessRuleName, "ACCEPT", "-R"});
            RoleData role = roleAccessSession.findRole(ROLENAME);
            AccessRuleData rule = role.getAccessRules().get((AccessRuleData.generatePrimaryKey(ROLENAME, accessRuleName)));
            assertNotNull("Rule " + accessRuleName + " was not added to role via CLI", rule);
    }
    
}
