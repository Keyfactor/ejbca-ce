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
package org.ejbca.core.ejb.roles;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Collection;
import java.util.LinkedList;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class ComplexRoleManagementSessionTest extends RoleUsingTestCase {

    private ComplexRoleManagementSessionRemote complexRoleManagementSession = JndiHelper.getRemoteSession(ComplexRoleManagementSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    @Before
    public void setup() throws Exception {
        setUpAuthTokenAndRole("RoleManagementSessionTest");
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    @Test
    public void testReplaceAccessRulesInRole() throws RoleExistsException, AuthorizationDeniedException, AccessRuleNotFoundException,
            RoleNotFoundException {
        RoleData ralph = roleManagementSession.create(roleMgmgToken, "Ralph");
        try {
            Collection<AccessRuleData> accessRules = new LinkedList<AccessRuleData>();
            accessRules.add(new AccessRuleData(ralph.getRoleName(), "/ToBeMerged", AccessRuleState.RULE_ACCEPT, false));
            AccessRuleData toBeRemoved = new AccessRuleData(ralph.getRoleName(), "/ToBeRemoved", AccessRuleState.RULE_ACCEPT, false);
            accessRules.add(toBeRemoved);
            ralph = roleManagementSession.addAccessRulesToRole(roleMgmgToken, ralph, accessRules);
            accessRules = new LinkedList<AccessRuleData>();
            AccessRuleData toBeMerged = new AccessRuleData(ralph.getRoleName(), "/ToBeMerged", AccessRuleState.RULE_DECLINE, false);
            AccessRuleData toBeAdded = new AccessRuleData(ralph.getRoleName(), "/ToBeAdded", AccessRuleState.RULE_DECLINE, false);
            accessRules.add(toBeMerged);
            accessRules.add(toBeAdded);
            ralph = complexRoleManagementSession.replaceAccessRulesInRole(roleMgmgToken, ralph, accessRules);
            assertNotNull("Rule to be merged was removed", ralph.getAccessRules().get(toBeMerged.getPrimaryKey()));
            assertEquals("Rule to be merged was not merged", AccessRuleState.RULE_DECLINE, ralph.getAccessRules().get(toBeMerged.getPrimaryKey()).getInternalState());
            assertNotNull("Rule to be added was not added", ralph.getAccessRules().get(toBeAdded.getPrimaryKey()));
            assertNull("Rule to be removed was not removed", ralph.getAccessRules().get(toBeRemoved.getPrimaryKey()));
        } finally {
            roleManagementSession.remove(roleMgmgToken, ralph);
        }
    }
}
