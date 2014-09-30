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
package org.ejbca.core.model.authorization;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class AccessRuleTemplateTest {

    /**
     * This test checks the compareToAccessRuleData method in AccessRuleTemplate, making sure 
     * that a rule and a template with the same states and recursive modes return true. 
     */
    @Test
    public void TestCompareToAccessRuleData() {
        AccessRuleTemplate template = new AccessRuleTemplate("/monkey", AccessRuleState.RULE_ACCEPT, false);
        AccessRuleData rule = new AccessRuleData("ape", "/monkey", AccessRuleState.RULE_ACCEPT, false);
        assertTrue(template.compareToAccessRuleData(rule));
        rule = new AccessRuleData("ape", "/monkey", AccessRuleState.RULE_ACCEPT, true);
        assertFalse(template.compareToAccessRuleData(rule));
        rule = new AccessRuleData("ape", "/monkey", AccessRuleState.RULE_DECLINE, false);
        assertFalse(template.compareToAccessRuleData(rule));
    }

}
