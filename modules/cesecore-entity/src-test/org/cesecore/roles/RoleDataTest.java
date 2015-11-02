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
package org.cesecore.roles;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.junit.Test;

/**
 * Unit tests on methods in RoleData
 * 
 * @version $Id$
 *
 */
public class RoleDataTest {
    
    @Test
    public void testHasAccessToRule() {
        final String roleName = "role";
        RoleData testRole = new RoleData(1, roleName);
        Map<Integer, AccessRuleData> accessRules = new HashMap<Integer, AccessRuleData>();
        accessRules.put(1, new AccessRuleData(roleName, "/foo", AccessRuleState.RULE_ACCEPT, true));
        accessRules.put(2, new AccessRuleData(roleName, "/foo/bar", AccessRuleState.RULE_DECLINE, true));
        accessRules.put(3, new AccessRuleData(roleName, "/xyz", AccessRuleState.RULE_DECLINE, true));
        accessRules.put(4, new AccessRuleData(roleName, "/xyz_abc", AccessRuleState.RULE_ACCEPT, true));
        testRole.setAccessRules(accessRules);
        assertFalse("Was incorrectly given access to a rule that should have state unknown", testRole.hasAccessToRule("/"));
        assertTrue("Should have been given access to a rule which was explicitly accepted.", testRole.hasAccessToRule("/foo"));
        assertFalse("Was incorrectly given access to a rule which was explicitly denied.",testRole.hasAccessToRule("/foo/bar"));
        assertFalse("Was incorrectly given access to a rule which was denied in a subrule.",testRole.hasAccessToRule("/foo/bar/xyz"));  
        assertTrue("Should have been given access to a rule with a similar name as one denied", testRole.hasAccessToRule("/xyz_abc"));
    }

}
