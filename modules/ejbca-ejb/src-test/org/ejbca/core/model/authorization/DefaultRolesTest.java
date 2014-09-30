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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class DefaultRolesTest {

    private static String ROLENAME = "test";
    
    @Test
    public void testEquals() {
        String roleName = DefaultRoles.SUPERADMINISTRATOR.getName();
        assertTrue(DefaultRoles.SUPERADMINISTRATOR.equals(roleName));
    }

    
    @Test
    public void testIdentifyWithExternalRules() {
        Collection<AccessRuleData> raAdminRuleSet = new ArrayList<AccessRuleData>();
        String externalRule = "/nonexistingrule";
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false)); 
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, externalRule, AccessRuleState.RULE_ACCEPT, false));  
        Collection<AccessRuleTemplate> externalRules = new ArrayList<AccessRuleTemplate>();
        externalRules.add(new AccessRuleTemplate(externalRule, AccessRuleState.RULE_ACCEPT, false));
        externalRules.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false));      
        assertEquals(DefaultRoles.RAADMINISTRATOR, DefaultRoles.identifyFromRuleSet(raAdminRuleSet, externalRules));
    }
    
    @Test
    public void testIdentifyFromCorrectRuleSet() {
        Collection<AccessRuleData> raAdminRuleSet = new ArrayList<AccessRuleData>();
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        raAdminRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false));      
        assertEquals(DefaultRoles.RAADMINISTRATOR, DefaultRoles.identifyFromRuleSet(raAdminRuleSet, new ArrayList<AccessRuleTemplate>()));
    }
    
    @Test
    public void testIdentifyFromSuperflousRuleSet() {
        Collection<AccessRuleData> customRuleSet = new ArrayList<AccessRuleData>();
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, AccessRuleState.RULE_ACCEPT, false));      

        assertEquals(DefaultRoles.CUSTOM, DefaultRoles.identifyFromRuleSet(customRuleSet, new ArrayList<AccessRuleTemplate>()));
    }
    
    @Test
    public void testIdentifyFromCustomRuleSet() {
        Collection<AccessRuleData> customRuleSet = new ArrayList<AccessRuleData>();
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));
        customRuleSet.add(new AccessRuleData(ROLENAME, AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false));    
        assertEquals(DefaultRoles.CUSTOM, DefaultRoles.identifyFromRuleSet(customRuleSet, new ArrayList<AccessRuleTemplate>()));
    }
    
    @Test
    public void testGetDefaultRoleFromName() {
        assertEquals(DefaultRoles.CAADMINISTRATOR, DefaultRoles.getDefaultRoleFromName(DefaultRoles.CAADMINISTRATOR.getName()));
    }
}
