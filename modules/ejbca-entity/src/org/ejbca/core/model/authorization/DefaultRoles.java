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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.keybind.InternalKeyBindingRules;

/**
 * Represents a set of predefined roles.
 * 
 * @version $Id$
 * 
 */
public enum DefaultRoles {
    CUSTOM("CUSTOM"), 
    SUPERADMINISTRATOR("SUPERADMINISTRATOR", 
            new AccessRuleTemplate(StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true)), 
    CAADMINISTRATOR("CAADMINISTRATOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(StandardRules.CAFUNCTIONALITY.resource(), AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(StandardRules.CAVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.CERTIFICATEPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_EDITPUBLISHER, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWPUBLISHER, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AuditLogRules.LOG.resource(), AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(StandardRules.EDITROLES.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.VIEWROLES.resource(), AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(CryptoTokenRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true),
            /*
             * Note:
             * We DO NOT allow CA Administrators to USE CryptoTokens, since this would mean that they could
             * bind any existing CryptoToken to a new CA and access the keys.
             * new AccessRuleTemplate(CryptoTokenRules.USE.resource(), AccessRuleState.RULE_ACCEPT, true)
             */
            new AccessRuleTemplate(InternalKeyBindingRules.DELETE.resource(), AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(InternalKeyBindingRules.MODIFY.resource(), AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(InternalKeyBindingRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true)
    ),
    RAADMINISTRATOR("RAADMINISTRATOR",
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false)),
    SUPERVISOR("SUPERVISOR",
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false)), 
    AUDITOR("AUDITOR", 
            new AccessRuleTemplate(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRuleState.RULE_ACCEPT, false), 
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true), 
            new AccessRuleTemplate(InternalKeyBindingRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(StandardRules.CAVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.CERTIFICATEPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(CryptoTokenRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWPUBLISHER, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.SERVICES_VIEW, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW, AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleTemplate(StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.EKUCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(StandardRules.VIEWROLES.resource(), AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false)
            ),
    HARDTOKENISSUER("HARDTOKENISSUER");

    private static Map<String, DefaultRoles> nameToObjectMap = new HashMap<String, DefaultRoles>();
    private String name;
    private Collection<AccessRuleTemplate> ruleSet = new ArrayList<AccessRuleTemplate>();

    static {
        for (DefaultRoles defaultRole : DefaultRoles.values()) {
            nameToObjectMap.put(defaultRole.getName(), defaultRole);
        }
    }

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

    private boolean matchesRuleSet(final Collection<AccessRuleData> rules, final Collection<AccessRuleTemplate> externalRules) {
        Map<String, AccessRuleTemplate> combinedRules = new HashMap<String, AccessRuleTemplate>();
        for (AccessRuleTemplate template : ruleSet) {
            combinedRules.put(template.getAccessRuleName(), template);
        }
        for (AccessRuleTemplate template : externalRules) {
            combinedRules.put(template.getAccessRuleName(), template);
        }
        if (combinedRules.size() != rules.size()) {
            ruleloop : for(AccessRuleTemplate combinedRule : combinedRules.values()) {
                for(AccessRuleData rule : rules) {
                    if(rule.getAccessRuleName().equals(combinedRule.getAccessRuleName())) {
                        continue ruleloop;
                    }                    
                }
            }
            return false;
        } else {
            for (AccessRuleData rule : rules) {
                if (!combinedRules.containsKey(rule.getAccessRuleName())) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * Identifies if the given rules match 
     * 
     * @param rules a map of rules
     * @param a list of rule templates that define rules that won't disqualify a match
     * @return the matching default role, or DefaultRoles.CUSTOM if no match is found
     * 
     */
    public static DefaultRoles identifyFromRuleSet(final Collection<AccessRuleData> rules, final Collection<AccessRuleTemplate> externalRules) {
        for (DefaultRoles defaultRole : DefaultRoles.values()) {
            if (defaultRole.matchesRuleSet(rules, externalRules)) {
                return defaultRole;
            }
        }
        return DefaultRoles.CUSTOM;
    }

    public static DefaultRoles getDefaultRoleFromName(String name) {
        return nameToObjectMap.get(name);
    }
}
