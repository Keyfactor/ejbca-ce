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
package org.ejbca.core.model.authorization;

import java.util.ArrayList;
import java.util.Collection;

import org.cesecore.authorization.rules.AccessRuleState;

/**
 * Represents a set of predefined roles.
 * 
 * @version $Id$
 * 
 */
public enum DefaultRoles {
    CUSTOM("CUSTOM"), 
    SUPERADMINISTRATOR("SUPERADMINISTRATOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false)
            ), 
    CAADMINISTRATOR("CAADMINISTRATOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_CAFUNCTIONALTY, AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_LOGFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, AccessRuleState.RULE_ACCEPT, false)
            ), 
    RAADMINISTRATOR("RAADMINISTRATOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false)
            ),
    SUPERVISOR("SUPERVISOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWLOG, AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false)
            ), 
    HARDTOKENISSUER("HARDTOKENISSUER");

    private String name;
    private Collection<AccessRuleTemplate> ruleSet = new ArrayList<AccessRuleTemplate>();

    private DefaultRoles(String name, AccessRuleTemplate... templates) {
        this.name = name;
        for (AccessRuleTemplate template : templates) {
            ruleSet.add(template);
        }
    }

    public Collection<AccessRuleTemplate> getRuleSet() {
        return ruleSet;
    }

    public String getName() {
        return name;
    }

    public boolean equals(String roleName) {
        if (roleName == null) {
            return false;
        } else {
            return name.equals(roleName);
        }
    }

}
