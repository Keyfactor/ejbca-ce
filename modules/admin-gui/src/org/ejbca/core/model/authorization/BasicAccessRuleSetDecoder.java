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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleState;

/**
 * A class used as a help class for displaying and configuring basic access rules
 * 
 * @version $Id$
 */
public class BasicAccessRuleSetDecoder implements Serializable {

    private static final long serialVersionUID = -5005027426714699357L;

    private ArrayList<AccessRuleTemplate> currentruleset = new ArrayList<AccessRuleTemplate>();

    /**
     * Tries to encode a advanced rule set into basic ones. Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetDecoder(String currentRoleTemplate, Collection<Integer> currentcas, Collection<Integer> currentendentityrules,
            Collection<Integer> currentendentityprofiles, Collection<Integer> currentotherrules) {

        if (DefaultRoles.SUPERADMINISTRATOR.getName().equals(currentRoleTemplate)) {
            currentruleset.addAll(DefaultRoles.SUPERADMINISTRATOR.getRuleSet());
        } else {
            addCARules(currentRoleTemplate, currentcas);
            addOtherRules(currentRoleTemplate, currentotherrules);
            if (DefaultRoles.CAADMINISTRATOR.equals(currentRoleTemplate)) {
                currentruleset.addAll(DefaultRoles.CAADMINISTRATOR.getRuleSet());
            } else {
                addEndEntityRules(currentendentityprofiles, currentendentityrules);
                if (DefaultRoles.RAADMINISTRATOR.equals(currentRoleTemplate)) {
                    currentruleset.addAll(DefaultRoles.RAADMINISTRATOR.getRuleSet());
                }
                if (DefaultRoles.SUPERVISOR.equals(currentRoleTemplate)) {
                    currentruleset.addAll(DefaultRoles.SUPERVISOR.getRuleSet());
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

    private void addCARules(String roleName, Collection<Integer> currentcas) {
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

        this.currentruleset.addAll(carules);

    }

    private void addOtherRules(String roleName, Collection<Integer> currentotherrules) {
        Iterator<Integer> iter = currentotherrules.iterator();
        while (iter.hasNext()) {
            Integer next = (Integer) iter.next();

            if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG))) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWLOG, AccessRuleState.RULE_ACCEPT, true));
            } else if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS))) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
            }
        }
    }

    private void addEndEntityRules(Collection<Integer> currentendentityprofiles, Collection<Integer> currentendentityrules) {
        ArrayList<String> endentityrules = new ArrayList<String>();

        for (Integer next : currentendentityrules) {
            if (next == BasicAccessRuleSet.ENDENTITY_VIEW) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.VIEW_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHISTORY) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HISTORY_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_CREATE) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.CREATE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_DELETE) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.DELETE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_EDIT) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.EDIT_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_REVOKE) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.REVOKE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_KEYRECOVER) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.KEYRECOVERY_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_APPROVE) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.APPROVAL_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWPUK) {
                currentruleset.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWPUKS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
            }
        }

        addEndEntityProfiles(currentendentityprofiles, endentityrules);
    }

    private void addEndEntityProfiles(Collection<Integer> currentendentityprofiles, Collection<String> endentityrules) {
        boolean allexists = false;
        Iterator<Integer> iter = currentendentityprofiles.iterator();
        ArrayList<AccessRuleTemplate> profilerules = new ArrayList<AccessRuleTemplate>();
        while (iter.hasNext() && !allexists) {
            Integer next = (Integer) iter.next();
            if (next.intValue() == BasicAccessRuleSet.ENDENTITYPROFILE_ALL) {
                allexists = true;
                break;
            }
            Iterator<String> iter2 = endentityrules.iterator();
            String profilerule = AccessRulesConstants.ENDENTITYPROFILEPREFIX + next.toString();
            while (iter2.hasNext()) {
                String nextrule = (String) iter2.next();
                profilerules.add(new AccessRuleTemplate(profilerule + nextrule, AccessRuleState.RULE_ACCEPT, false));
            }
        }

        if (allexists) {
            profilerules.clear();
            profilerules.add(new AccessRuleTemplate(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        }
        currentruleset.addAll(profilerules);
    }

}
