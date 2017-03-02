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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleState;

/**
 * A class used as a help class for displaying and configuring basic access rules
 * 
 * @version $Id$
 */
@Deprecated // See deprecation of RolesManagedBean
public class BasicAccessRuleSetDecoder implements Serializable {

    private static final long serialVersionUID = -5005027426714699357L;

    private ArrayList<AccessRuleTemplate> currentruleset = new ArrayList<AccessRuleTemplate>();

    /**
     * Tries to encode a advanced rule set into basic ones. Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetDecoder(String currentRoleTemplate, Collection<Integer> currentcas, Collection<Integer> currentendentityrules,
            Collection<Integer> currentendentityprofiles, List<String> internalKeybindingRules, Collection<Integer> currentotherrules) {

        if (DefaultRoles.SUPERADMINISTRATOR.getName().equals(currentRoleTemplate)) {
            currentruleset.addAll(DefaultRoles.SUPERADMINISTRATOR.getRuleSet());
        } else {
            currentruleset.addAll(getCaRules(currentRoleTemplate, currentcas));
            currentruleset.addAll(getOtherRules(currentRoleTemplate, currentotherrules));
            if (DefaultRoles.CAADMINISTRATOR.equals(currentRoleTemplate)) {
                currentruleset.addAll(DefaultRoles.CAADMINISTRATOR.getRuleSet());
                currentruleset.addAll(getInternalKeybindingRules(currentRoleTemplate, internalKeybindingRules));
            } else {
                currentruleset.addAll(getEndEntityRules(currentendentityprofiles, currentendentityrules));
                if (DefaultRoles.RAADMINISTRATOR.equals(currentRoleTemplate)) {
                    currentruleset.addAll(DefaultRoles.RAADMINISTRATOR.getRuleSet());
                }
                if (DefaultRoles.SUPERVISOR.equals(currentRoleTemplate)) {
                    currentruleset.addAll(DefaultRoles.SUPERVISOR.getRuleSet());
                }
                if (DefaultRoles.AUDITOR.equals(currentRoleTemplate)) {
                    currentruleset.addAll(DefaultRoles.AUDITOR.getRuleSet());
                }
            }
        }

    }

    /**
     * Returns the current advanced rule set.
     * 
     * @return a Collection of AccessRule
     */
    public Collection<AccessRuleTemplate> getCurrentAdvancedRuleSet() {
        return currentruleset;
    }

    public static Collection<AccessRuleTemplate> getCaRules(String roleName, Collection<Integer> currentcas) {
        Collection<AccessRuleTemplate> result = new ArrayList<AccessRuleTemplate>();
        boolean allcafound = false;
        List<AccessRuleTemplate> carules = new ArrayList<AccessRuleTemplate>();
        for (Integer caId : currentcas) {
            if (caId.equals(Integer.valueOf(BasicAccessRuleSet.CA_ALL))) {
                allcafound = true;
                break;
            }
            carules.add(new AccessRuleTemplate(StandardRules.CAACCESS.resource() + caId.toString(), AccessRuleState.RULE_ACCEPT, false));
        }
        if (allcafound) {
            carules.clear();
            carules.add(new AccessRuleTemplate(StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        }
        result.addAll(carules);
        return result;

    }
    
    public static List<AccessRuleTemplate> getInternalKeybindingRules(String rolename, List<String> currentInternalKeybindingRules) {
        List<AccessRuleTemplate> result = new ArrayList<AccessRuleTemplate>();
        for(String rules : currentInternalKeybindingRules) {
            result.add(new AccessRuleTemplate(rules, AccessRuleState.RULE_ACCEPT, true));
        }
        return result;
    }

    public static Collection<AccessRuleTemplate> getOtherRules(String roleName, Collection<Integer> currentOtherRules) {
        Collection<AccessRuleTemplate> result = new ArrayList<AccessRuleTemplate>();
        for(Integer next : currentOtherRules) {
            if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG))) {
                result.add(new AccessRuleTemplate(AuditLogRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true));
            } else if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS))) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
            }
        }
        return result;
    }

    public static Collection<AccessRuleTemplate> getEndEntityRules(Collection<Integer> currentendentityprofiles, Collection<Integer> currentendentityrules) {
        List<String> endentityrules = new ArrayList<String>();
        Collection<AccessRuleTemplate> result = new ArrayList<AccessRuleTemplate>();
        for (Integer next : currentendentityrules) {
            if (next == BasicAccessRuleSet.ENDENTITY_VIEW) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.VIEW_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHISTORY) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.VIEW_END_ENTITY_HISTORY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_CREATE) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.CREATE_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_DELETE) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.DELETE_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_EDIT) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.EDIT_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_REVOKE) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.REVOKE_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_KEYRECOVER) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.KEYRECOVERY_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_APPROVE) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.APPROVE_END_ENTITY);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWPUK) {
                result.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWPUKS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
            }
        }

        result.addAll(getEndEntityProfileRules(currentendentityprofiles, endentityrules));
        return result;
    }

    private static Collection<AccessRuleTemplate> getEndEntityProfileRules(Collection<Integer> currentendentityprofiles, Collection<String> endentityrules) {
        boolean allexists = false;
        ArrayList<AccessRuleTemplate> profilerules = new ArrayList<AccessRuleTemplate>();
        for(Integer next : currentendentityprofiles) {
            if (next.intValue() == BasicAccessRuleSet.ENDENTITYPROFILE_ALL) {
                allexists = true;
                break;
            }
            String profilerule = AccessRulesConstants.ENDENTITYPROFILEPREFIX + next.toString();
            profilerules.add(new AccessRuleTemplate(profilerule, AccessRuleState.RULE_ACCEPT, false));
            for(String nextrule : endentityrules) {
                profilerules.add(new AccessRuleTemplate(profilerule + nextrule, AccessRuleState.RULE_ACCEPT, false));
            }
        }

        if (allexists) {
            profilerules.clear();
            profilerules.add(new AccessRuleTemplate(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        }
       return profilerules;
    }

}
