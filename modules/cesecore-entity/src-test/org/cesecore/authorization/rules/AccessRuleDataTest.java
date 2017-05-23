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
package org.cesecore.authorization.rules;

import static org.junit.Assert.assertEquals;

import org.cesecore.authorization.access.AccessTreeState;
import org.junit.Test;

/**
 * Unit tests for the AccessRuleData class
 * 
 * @version $Id$
 *
 */
public class AccessRuleDataTest {

    @SuppressWarnings("deprecation")
    @Test
    public void testSetState() {
        AccessRuleData accessRule = new AccessRuleData(AccessRuleData.generatePrimaryKey("Ape", "Monkey"), "Monkey", AccessRuleState.RULE_NOTUSED, false);
        assertEquals(AccessTreeState.STATE_UNKNOWN, accessRule.getTreeState());
        accessRule.setInternalState(AccessRuleState.RULE_ACCEPT);
        assertEquals(AccessTreeState.STATE_ACCEPT, accessRule.getTreeState());
        accessRule.setRecursive(true);
        assertEquals(AccessTreeState.STATE_ACCEPT_RECURSIVE, accessRule.getTreeState());
        accessRule.setRecursive(false);
        accessRule.setInternalState(AccessRuleState.RULE_DECLINE);
        assertEquals(AccessTreeState.STATE_DECLINE, accessRule.getTreeState());
    }
    
    @SuppressWarnings("deprecation")
    @Test
    public void testGeneratePrimaryKey() {
        final String roleName = "monkey";
        final String accessRuleName = "do as I say";
        final String accessRuleNameWithWhitespace = "   do as I say   ";
        assertEquals((roleName.hashCode() ^ accessRuleName.hashCode()), AccessRuleData.generatePrimaryKey(roleName, accessRuleName));
        assertEquals((roleName.hashCode() ^ accessRuleName.hashCode()), AccessRuleData.generatePrimaryKey(roleName, accessRuleNameWithWhitespace));
        assertEquals((0 ^ accessRuleName.hashCode()), AccessRuleData.generatePrimaryKey(null, accessRuleName));
        assertEquals((roleName.hashCode() ^ 0), AccessRuleData.generatePrimaryKey(roleName, null));
    }
    
}
