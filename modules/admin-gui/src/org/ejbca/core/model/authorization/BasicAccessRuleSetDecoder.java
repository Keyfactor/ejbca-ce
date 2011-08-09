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

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.roles.RoleData;

/**
 * A class used as a help class for displaying and configuring basic access rules
 * 
 * @version $Id$
 */
public class BasicAccessRuleSetDecoder implements Serializable {

    private static final long serialVersionUID = -5005027426714699357L;

    private ArrayList<AccessRuleData> currentruleset = new ArrayList<AccessRuleData>();

    /**
     * Tries to encode a advanced rule set into basic ones. Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetDecoder(RoleData currentrole, Collection<Integer> currentcas, Collection<Integer> currentendentityrules,
            Collection<Integer> currentendentityprofiles, Collection<Integer> currentotherrules) {

        if (DefaultRoles.SUPERADMINISTRATOR.equals(currentrole)) {
            currentruleset.add(new AccessRuleData(DefaultRoles.SUPERADMINISTRATOR.getName(), AccessRulesConstants.ROLE_SUPERADMINISTRATOR,
                    AccessRuleState.RULE_ACCEPT, false));
        } else {
            addCARules(currentrole.getRoleName(), currentcas);
            addOtherRules(currentrole.getRoleName(), currentotherrules);
            if (DefaultRoles.CAADMINISTRATOR.equals(currentrole)) {
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.ROLE_ADMINISTRATOR,
                        AccessRuleState.RULE_ACCEPT, false));

                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.REGULAR_CAFUNCTIONALTY,
                        AccessRuleState.RULE_ACCEPT, true));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.REGULAR_LOGFUNCTIONALITY,
                        AccessRuleState.RULE_ACCEPT, true));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.REGULAR_RAFUNCTIONALITY,
                        AccessRuleState.RULE_ACCEPT, true));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY,
                        AccessRuleState.RULE_ACCEPT, false));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(),
                        AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES, AccessRuleState.RULE_ACCEPT, false));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.ENDENTITYPROFILEBASE,
                        AccessRuleState.RULE_ACCEPT, true));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS,
                        AccessRuleState.RULE_ACCEPT, false));
                currentruleset.add(new AccessRuleData(DefaultRoles.CAADMINISTRATOR.getName(), AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES,
                        AccessRuleState.RULE_ACCEPT, false));

            } else {
                addEndEntityRules(currentrole.getRoleName(), currentendentityprofiles, currentendentityrules);
                if (DefaultRoles.RAADMINISTRATOR.equals(currentrole)) {
                    currentruleset.add(new AccessRuleData(DefaultRoles.RAADMINISTRATOR.name(), AccessRulesConstants.ROLE_ADMINISTRATOR,
                            AccessRuleState.RULE_ACCEPT, false));
                    currentruleset.add(new AccessRuleData(DefaultRoles.RAADMINISTRATOR.name(), AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                            AccessRuleState.RULE_ACCEPT, false));
                    currentruleset.add(new AccessRuleData(DefaultRoles.RAADMINISTRATOR.name(), AccessRulesConstants.REGULAR_STORECERTIFICATE,
                            AccessRuleState.RULE_ACCEPT, false));
                    currentruleset.add(new AccessRuleData(DefaultRoles.RAADMINISTRATOR.name(), AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                            AccessRuleState.RULE_ACCEPT, false));
                }
                if (DefaultRoles.SUPERVISOR.equals(currentrole)) {
                    currentruleset.add(new AccessRuleData(DefaultRoles.SUPERVISOR.name(), AccessRulesConstants.ROLE_ADMINISTRATOR,
                            AccessRuleState.RULE_ACCEPT, false));
                    currentruleset.add(new AccessRuleData(DefaultRoles.SUPERVISOR.name(), AccessRulesConstants.REGULAR_VIEWLOG,
                            AccessRuleState.RULE_ACCEPT, true));
                    currentruleset.add(new AccessRuleData(DefaultRoles.SUPERVISOR.name(), AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                            AccessRuleState.RULE_ACCEPT, false));
                }
            }
        }

    }

    /**
     * Returns the current advanced rule set.
     * 
     * @return a Collection of AccessRule
     */
    public Collection<AccessRuleData> getCurrentAdvancedRuleSet() {
        return currentruleset;
    }

    private void addCARules(String roleName, Collection<Integer> currentcas) {
        boolean allcafound = false;

       List<AccessRuleData> carules = new ArrayList<AccessRuleData>();
        for(Integer caId : currentcas) {
            if (caId.equals(Integer.valueOf(BasicAccessRuleSet.CA_ALL))) {
                allcafound = true;
                break;
            }
            carules.add(new AccessRuleData(roleName, AccessRulesConstants.CAPREFIX + caId.toString(), AccessRuleState.RULE_ACCEPT, false));
        }

        if (allcafound) {
            carules.clear();
            carules.add(new AccessRuleData(roleName, AccessRulesConstants.CABASE, AccessRuleState.RULE_ACCEPT, true));
        }

        this.currentruleset.addAll(carules);

    }

    private void addOtherRules(String roleName, Collection<Integer> currentotherrules) {
        Iterator<Integer> iter = currentotherrules.iterator();
        while (iter.hasNext()) {
            Integer next = (Integer) iter.next();

            if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG))) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWLOG, AccessRuleState.RULE_ACCEPT, true));
            } else if (next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS))) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
            }
        }
    }

    private void addEndEntityRules(String roleName, Collection<Integer> currentendentityprofiles, Collection<Integer> currentendentityrules) {
        ArrayList<String> endentityrules = new ArrayList<String>();

        for (Integer next : currentendentityrules) {
            if (next == BasicAccessRuleSet.ENDENTITY_VIEW) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.VIEW_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHISTORY) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HISTORY_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWHARDTOKENS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_CREATE) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.CREATE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_DELETE) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.DELETE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_EDIT) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.EDIT_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_REVOKE) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.REVOKE_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_KEYRECOVER) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.KEYRECOVERY_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_APPROVE) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.APPROVAL_RIGHTS);
            } else if (next == BasicAccessRuleSet.ENDENTITY_VIEWPUK) {
                currentruleset.add(new AccessRuleData(roleName, AccessRulesConstants.REGULAR_VIEWPUKS, AccessRuleState.RULE_ACCEPT, false));
                endentityrules.add(AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
            }
        }

        addEndEntityProfiles(roleName, currentendentityprofiles, endentityrules);
    }

    private void addEndEntityProfiles(String ruleName, Collection<Integer> currentendentityprofiles, Collection<String> endentityrules) {
        boolean allexists = false;
        Iterator<Integer> iter = currentendentityprofiles.iterator();
        ArrayList<AccessRuleData> profilerules = new ArrayList<AccessRuleData>();
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
                profilerules.add(new AccessRuleData(ruleName, profilerule + nextrule, AccessRuleState.RULE_ACCEPT, false));
            }
        }

        if (allexists) {
            profilerules.clear();
            profilerules.add(new AccessRuleData(ruleName, AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRuleState.RULE_ACCEPT, true));
        }
        currentruleset.addAll(profilerules);
    }

}
