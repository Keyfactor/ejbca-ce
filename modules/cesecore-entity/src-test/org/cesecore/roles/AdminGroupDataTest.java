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

import java.util.Arrays;
import java.util.List;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.junit.Test;

/**
 * Unit tests on methods in RoleData
 * 
 * @version $Id$
 *
 */
@Deprecated
public class AdminGroupDataTest {
    
    @Test
    public void testHasAccessToRule() {
        final String roleName = "role";
        AdminGroupData testRole = new AdminGroupData(1, roleName);
        List<AccessRuleData> accessRules = Arrays.asList(
                new AccessRuleData(roleName, "/fuu", AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, "/foo/bar", AccessRuleState.RULE_DECLINE, true),
                new AccessRuleData(roleName, "/xyz", AccessRuleState.RULE_DECLINE, true),
                new AccessRuleData(roleName, "/xyz_abc", AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, "/recursive", AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, "/recursivewithdenied", AccessRuleState.RULE_ACCEPT, true),
                new AccessRuleData(roleName, "/recursivewithdenied/denied", AccessRuleState.RULE_DECLINE, false),
                new AccessRuleData(roleName, "/non_recursive", AccessRuleState.RULE_ACCEPT, false)
                );
        assertFalse("Was incorrectly given access to a rule that should have state unknown", testRole.hasAccessToRule("/", false, accessRules));
        assertTrue("Should have been given access to a rule which was explicitly accepted.", testRole.hasAccessToRule("/fuu", false, accessRules));
        assertFalse("Was incorrectly given access to a rule which was explicitly denied.",testRole.hasAccessToRule("/foo/bar", false, accessRules));
        assertFalse("Was incorrectly given access to a rule which was denied in a subrule.",testRole.hasAccessToRule("/foo/bar/xyz", false, accessRules));  
        assertTrue("Should have been given access to a rule with a similar name as one denied", testRole.hasAccessToRule("/xyz_abc", false, accessRules));
        assertTrue("Should have been given access to a rule with recursive required", testRole.hasAccessToRule("/recursive", true, accessRules));
        assertTrue("Should have been given access to a rule with recursive allowed by parent", testRole.hasAccessToRule("/recursive/subrule", false, accessRules));
        assertTrue("Should have been given access to a rule with recursive required", testRole.hasAccessToRule("/recursive/subrule", true, accessRules));
        assertFalse("[Privilege escalation] Was incorrectly given access to a rule which was has declined in a subrule", testRole.hasAccessToRule("/recursivewithdenied", true, accessRules));
        assertFalse("Was incorrectly given access to a rule which was explicitly denied.", testRole.hasAccessToRule("/recursivewithdenied/denied", false, accessRules));
        assertFalse("Was incorrectly given access to a rule which was explicitly denied.", testRole.hasAccessToRule("/recursivewithdenied/denied", true, accessRules));
        assertFalse("Should not have been given access to a rule ", testRole.hasAccessToRule("/non_recursive", true, accessRules));
        assertFalse("Should not have been given access to a rule with recursive required", testRole.hasAccessToRule("/non_recursive", true, accessRules));
    }
    
    /**
     * Make sure that access to root is never given by mistake. 
     */
    @Test
    public void testHasAccessToRoot() {
        final String roleName = "role";
        AdminGroupData testRole = new AdminGroupData(1, roleName);
        List<AccessRuleData> accessRules = Arrays.asList(
                new AccessRuleData(roleName, "/fuu", AccessRuleState.RULE_ACCEPT, true)
                );
        assertFalse("Was incorrectly given access to root.", testRole.hasAccessToRule("/", false, accessRules));
    }
}
