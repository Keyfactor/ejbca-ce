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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.keybind.InternalKeyBindingRules;

/**
 * A class used as a help class for displaying and configuring basic access rules
 * 
 * @version $Id$
 */
public class BasicAccessRuleSetEncoder implements Serializable {

    private static final long serialVersionUID = 2823487794362088820L;

    private boolean forceadvanced = false;

    private Collection<String> namesOfAvailableRoles = new ArrayList<String>();
    private Set<Integer> currentcas = new HashSet<Integer>();
    private Set<Integer> availablecas = new HashSet<Integer>();
    private Set<Integer> currentendentityrules = new HashSet<Integer>();
    private ArrayList<Integer> availableendentityrules = new ArrayList<Integer>();
    private Set<Integer> currentendentityprofiles = new HashSet<Integer>();
    private Set<Integer> availableendentityprofiles = new HashSet<Integer>();
    private Set<Integer> currentotherrules = new HashSet<Integer>();
    private List<Integer> availableotherrules = new ArrayList<Integer>();
    private List<String> currentInternalKeybindingRules = new ArrayList<String>();
    private List<String> availableInternalKeybindingRules = new ArrayList<String>();

    /**
     * Tries to encode a advanced ruleset into basic ones. Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetEncoder(Collection<AccessRuleData> currentaccessrules, Collection<String> availableaccessrules, boolean usehardtokens,
            boolean usekeyrecovery) {
        HashSet<String> aar = new HashSet<String>();
        aar.addAll(availableaccessrules);
        for (AccessRuleData accessRule : currentaccessrules) {
            aar.add(accessRule.getAccessRuleName());
        }
        initAvailableRoles(aar);
        initAvailableRules(usehardtokens, usekeyrecovery, aar);

        initCurrentRules(currentaccessrules);

    }

    /**
     * Returns true if basic configuration of access rules isn't possible.
     */
    public boolean getForceAdvanced() {
        return forceadvanced;
    }

    /**
     * Returns a Collection of basic roles the administrator is authorized to configure.
     * 
     * @return a Collection of BasicAccessRuleSet.ROLE_constants (Integer)
     */
    public Collection<String> getAvailableRoles() {
        return namesOfAvailableRoles;
    }

    /**
     * @return a Collection of CAids the role is authorized to or BasicAccessRuleSet.CA_ALL for all cas.
     */
    public Set<Integer> getCurrentCAs() {
        return currentcas;
    }

    /**
     * @return a Collection of available CAids or BasicAccessRuleSet.CA_ALL for all cas.
     */
    public Collection<Integer> getAvailableCAs() {
        return availablecas;
    }

    /**
     * @return a Collection of EndEntityRules the role is authorized to, BasicAccessRuleSet.ENDENTITY_ constants (Integer).
     */
    public Set<Integer> getCurrentEndEntityRules() {
        return currentendentityrules;
    }

    /**
     * @return a Collection of Internal Keybinding Rules the role is authorized to.
     */
    public List<String> getCurrentInternalKeyBindingRules() {
        return currentInternalKeybindingRules;
    }
    
    /**
     * @return a Collection of available EndEntityRules, BasicAccessRuleSet.ENDENTITY_ constants (Integer)
     */
    public Collection<Integer> getAvailableEndEntityRules() {
        return availableendentityrules;
    }

    /**
     * @return a Collection of authorized EndEntityProfileIds or BasicAccessRuleSet.ENDENTITYPROFILE_ALL for all
     */
    public Set<Integer> getCurrentEndEntityProfiles() {
        return currentendentityprofiles;
    }

    /**
     * @return a Collection of available EndEntityProfileIds or BasicAccessRuleSet.ENDENTITYPROFILE_ALL for all and entity profiles.
     */
    public Collection<Integer> getAvailableEndEntityProfiles() {
        return availableendentityprofiles;
    }

    /**
     * @return a Collection of authorized other rules. (Integer).
     */
    public Set<Integer> getCurrentOtherRules() {
        return currentotherrules;
    }

    /**
     * @return a Collection of available other rules (Integer).
     */
    public Collection<Integer> getAvailableOtherRules() {
        return availableotherrules;
    }
    
    public List<String> getAvailableInternalKeyBindingRules() {
        return availableInternalKeybindingRules;
    }

    private void initAvailableRoles(HashSet<String> availableruleset) {
        namesOfAvailableRoles.add(DefaultRoles.CUSTOM.getName());
        namesOfAvailableRoles.add(DefaultRoles.CAADMINISTRATOR.getName());
        namesOfAvailableRoles.add(DefaultRoles.RAADMINISTRATOR.getName());
        namesOfAvailableRoles.add(DefaultRoles.SUPERVISOR.getName());
        // Check if administrator can create superadministrators
        if (availableruleset.contains(StandardRules.ROLE_ROOT)) {
            namesOfAvailableRoles.add(DefaultRoles.SUPERADMINISTRATOR.getName());
        }

    }

    private void initAvailableRules(boolean usehardtokens, boolean usekeyrecovery, Collection<String> availableaccessrules) {
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEW));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));
        if (usehardtokens) {
            availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));
        }
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_CREATE));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_EDIT));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_DELETE));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_REVOKE));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_APPROVE));
        availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWPUK));
        if (usekeyrecovery) {
            availableendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_KEYRECOVER));
        }

        for(String nextrule : availableaccessrules) {          
            if (nextrule.equals(StandardRules.CAACCESSBASE.resource())) {
                this.availablecas.add(Integer.valueOf(BasicAccessRuleSet.CA_ALL));
            } else if (nextrule.startsWith(StandardRules.CAACCESS.resource())) {
                this.availablecas.add(Integer.valueOf(nextrule.substring(StandardRules.CAACCESS.resource().length())));
            } else if (nextrule.equals(AccessRulesConstants.ENDENTITYPROFILEBASE)) {
                this.availableendentityprofiles.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITYPROFILE_ALL));
            } else if (nextrule.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                if (nextrule.lastIndexOf('/') <= AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                    this.availableendentityprofiles.add(Integer.valueOf(nextrule.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length())));
                } else {
                    String tmpString = nextrule.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                    this.availableendentityprofiles.add(Integer.valueOf(tmpString.substring(0, tmpString.indexOf('/'))));
                }
            }
        }

        this.availableotherrules.add(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG));
        if (usehardtokens) {
            this.availableotherrules.add(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS));
        }
        availableInternalKeybindingRules.add(InternalKeyBindingRules.DELETE.resource());
        availableInternalKeybindingRules.add(InternalKeyBindingRules.MODIFY.resource());
        availableInternalKeybindingRules.add(InternalKeyBindingRules.VIEW.resource());
    }

    private void initCurrentRules(Collection<AccessRuleData> currentaccessrules) {
        HashMap<Integer, Integer> endentityrules = new HashMap<Integer, Integer>();

        Integer general = Integer.valueOf(0);
        endentityrules.put(general, Integer.valueOf(0));

        for (AccessRuleData accessRule : currentaccessrules) {
            if (accessRule.getAccessRuleName().startsWith(AccessRulesConstants.REGULAR_RAFUNCTIONALITY)
                    && accessRule.getAccessRuleName().length() > AccessRulesConstants.REGULAR_RAFUNCTIONALITY.length()
                    && !accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES)) {
                if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && !accessRule.getRecursive()) {
                    if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWENDENTITY)) {

                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEW));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEW));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_CREATEENDENTITY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_CREATE));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_CREATE));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_DELETEENDENTITY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_DELETE));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_DELETE));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_EDITENDENTITY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_EDIT));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_EDIT));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_REVOKE));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_REVOKE));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_KEYRECOVERY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_KEYRECOVER));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_KEYRECOVER));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_APPROVEENDENTITY)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_APPROVE));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_APPROVE));
                    } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWPUKS)) {
                        currentendentityrules.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITY_VIEWPUK));
                        endentityrules.put(general,
                                Integer.valueOf(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEWPUK));
                    }
                } else {
                    this.forceadvanced = true;
                    break;
                }
            } else {
                if (accessRule.getAccessRuleName().equals(AccessRulesConstants.ENDENTITYPROFILEBASE)) {
                    if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && accessRule.getRecursive()) {
                        this.currentendentityprofiles.add(Integer.valueOf(BasicAccessRuleSet.ENDENTITYPROFILE_ALL));
                    } else {
                        this.forceadvanced = true;
                        break;
                    }
                } else if (accessRule.getAccessRuleName().startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                    if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && !accessRule.getRecursive()) {
                        Integer profileid = null;
                        if (accessRule.getAccessRuleName().lastIndexOf('/') > AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                            String tmpString = accessRule.getAccessRuleName().substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                            profileid = Integer.valueOf(tmpString.substring(0, tmpString.indexOf('/')));
                        } else {
                            this.forceadvanced = true;
                            break;
                        }
                        int currentval = 0;
                        if (endentityrules.get(profileid) != null) {
                            currentval = ((Integer) endentityrules.get(profileid)).intValue();
                        }
                        if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.VIEW_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEW;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.VIEW_END_ENTITY_HISTORY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEWHISTORY;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.HARDTOKEN_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.CREATE_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_CREATE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.DELETE_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_DELETE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.EDIT_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_EDIT;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.REVOKE_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_REVOKE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.KEYRECOVERY_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_KEYRECOVER;
                        }
                        if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.APPROVE_END_ENTITY)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_APPROVE;
                        }
                        if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEWPUK;
                        }
                        endentityrules.put(profileid, Integer.valueOf(currentval));
                    } else {
                        this.forceadvanced = true;
                        break;
                    }
                } else {
                    if (accessRule.getAccessRuleName().equals(StandardRules.CAACCESSBASE.resource())) {
                        if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && accessRule.getRecursive()) {
                            this.currentcas.add(Integer.valueOf(BasicAccessRuleSet.CA_ALL));
                        } else {
                            this.forceadvanced = true;
                            break;
                        }
                    } else {
                        if (accessRule.getAccessRuleName().startsWith(StandardRules.CAACCESS.resource())) {
                            if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && !accessRule.getRecursive()) {
                                Integer caid = Integer.valueOf(accessRule.getAccessRuleName().substring(StandardRules.CAACCESS.resource().length()));
                                this.currentcas.add(caid);
                            } else {
                                this.forceadvanced = true;
                                break;
                            }
                        } else {
                            if (accessRule.getAccessRuleName().equals(AuditLogRules.VIEW.resource())) {
                                if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT && accessRule.getRecursive()) {
                                    this.currentotherrules.add(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG));
                                } else {
                                    this.forceadvanced = true;
                                    break;
                                }
                            } else if (accessRule.getAccessRuleName().equals(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS)) {
                                if (accessRule.getInternalState() == AccessRuleState.RULE_ACCEPT) {
                                    this.currentotherrules.add(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS));
                                } else {
                                    this.forceadvanced = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        int endentityruleval = endentityrules.get(general).intValue();
        for(Integer next : endentityrules.keySet()) {
            if (!next.equals(general)) {
                if (endentityrules.get(next).intValue() == endentityruleval) {
                    this.currentendentityprofiles.add(next);
                } else {
                    this.forceadvanced = true;
                }
            }
        }

    }

}
