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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;

/**
 * A class used as a help class for displaying and configuring basic access rules
 * 
 * @version $Id$
 */
public class BasicAccessRuleSetEncoder implements Serializable {

    private static final long serialVersionUID = 2823487794362088820L;

    private boolean forceadvanced = false;

    private String currentRoleName = null;
    private Collection<String> namesOfAvailableRoles = new ArrayList<String>();
    private HashSet<Integer> currentcas = new HashSet<Integer>();
    private HashSet<Integer> availablecas = new HashSet<Integer>();
    private HashSet<Integer> currentendentityrules = new HashSet<Integer>();
    private ArrayList<Integer> availableendentityrules = new ArrayList<Integer>();
    private HashSet<Integer> currentendentityprofiles = new HashSet<Integer>();
    private HashSet<Integer> availableendentityprofiles = new HashSet<Integer>();
    private HashSet<Integer> currentotherrules = new HashSet<Integer>();
    private List<Integer> availableotherrules = new ArrayList<Integer>();

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

        initCurrentRole(currentaccessrules);
        initCurrentRules(currentaccessrules);

    }

    /**
     * Returns true if basic configuration of access rules isn't possible.
     */
    public boolean getForceAdvanced() {
        return forceadvanced;
    }

    /**
     * Returns the current role of the administrator group.
     * 
     * @return one of the BasicAccessRuleSet ROLE_constants
     */
    public String getCurrentRole() {
        return currentRoleName;
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
     * @return a Collection of CAids the administratorgroup is authorized to or BasicAccessRuleSet.CA_ALL for all cas.
     */
    public HashSet<Integer> getCurrentCAs() {
        return currentcas;
    }

    /**
     * @return a Collection of available CAids or BasicAccessRuleSet.CA_ALL for all cas.
     */
    public Collection<Integer> getAvailableCAs() {
        return availablecas;
    }

    /**
     * @return a Collection of EndEntityRules the administratorgroup is authorized to, BasicAccessRuleSet.ENDENTITY_ constants (Integer).
     */
    public HashSet<Integer> getCurrentEndEntityRules() {
        return currentendentityrules;
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
    public HashSet<Integer> getCurrentEndEntityProfiles() {
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
    public HashSet<Integer> getCurrentOtherRules() {
        return currentotherrules;
    }

    /**
     * @return a Collection of available other rules (Integer).
     */
    public Collection<Integer> getAvailableOtherRules() {
        return availableotherrules;
    }

    private void initAvailableRoles(HashSet<String> availableruleset) {
        namesOfAvailableRoles.add(DefaultRoles.CAADMINISTRATOR.getName());
        namesOfAvailableRoles.add(DefaultRoles.RAADMINISTRATOR.getName());
        namesOfAvailableRoles.add(DefaultRoles.SUPERVISOR.getName());
        // Check if administrator can create superadministrators
        if (availableruleset.contains(AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            namesOfAvailableRoles.add(DefaultRoles.SUPERADMINISTRATOR.getName());
        }

    }

    private void initCurrentRole(Collection<AccessRuleData> currentaccessrules) {
        // Check if administrator is superadministrator

        if (currentaccessrules.size() > 0) {
            if (isSuperAdministrator(currentaccessrules)) {
                this.currentRoleName = DefaultRoles.SUPERADMINISTRATOR.getName();
            } else
            // Check if administrator is caadministrator
            if (isCAAdministrator(currentaccessrules)) {
                this.currentRoleName = DefaultRoles.CAADMINISTRATOR.getName();
            } else
            // Check if administrator is raadministrator
            if (isRAAdministrator(currentaccessrules)) {
                this.currentRoleName = DefaultRoles.RAADMINISTRATOR.getName();
            } else
            // Check if administrator is supervisor
            if (isSupervisor(currentaccessrules)) {
                this.currentRoleName = DefaultRoles.SUPERVISOR.getName();
            } else {
                this.forceadvanced = true;
            }
        } else {
            this.currentRoleName = null;
        }
    }

    private boolean isSuperAdministrator(Collection<AccessRuleData> currentaccessrules) {

        boolean returnval = false;
        if (currentaccessrules.size() == 1) {
            AccessRuleData ar = currentaccessrules.iterator().next();
            if (ar.getAccessRuleName().equals(AccessRulesConstants.ROLE_SUPERADMINISTRATOR) && ar.getInternalState() == AccessRuleState.RULE_ACCEPT
                    && !ar.getRecursive()) {
                returnval = true;
            }
        }

        return returnval;
    }

    private boolean isCAAdministrator(Collection<AccessRuleData> currentaccessrules) {
        boolean returnval = false;

        if (currentaccessrules.size() >= 7) {
            HashSet<String> requiredacceptrecrules = new HashSet<String>();
            requiredacceptrecrules.add(AccessRulesConstants.REGULAR_CAFUNCTIONALTY);
            requiredacceptrecrules.add(AccessRulesConstants.REGULAR_LOGFUNCTIONALITY);
            requiredacceptrecrules.add(AccessRulesConstants.REGULAR_RAFUNCTIONALITY);
            requiredacceptrecrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
            HashSet<String> requiredacceptnonrecrules = new HashSet<String>();
            requiredacceptnonrecrules.add(AccessRulesConstants.ROLE_ADMINISTRATOR);
            requiredacceptnonrecrules.add(AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY);
            requiredacceptnonrecrules.add(AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES);
            requiredacceptnonrecrules.add(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS);
            requiredacceptnonrecrules.add(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES);

            boolean illegal = false;
            for (AccessRuleData ar : currentaccessrules) {
                if (!isAllowedCAAdministratorRule(ar)) {
                    if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT && ar.getRecursive() && requiredacceptrecrules.contains(ar.getAccessRuleName())) {
                        requiredacceptrecrules.remove(ar.getAccessRuleName());
                    } else if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT && !ar.getRecursive() && requiredacceptnonrecrules.contains(ar.getAccessRuleName())) {
                        requiredacceptnonrecrules.remove(ar.getAccessRuleName());
                    } else {
                        illegal = true;
                        break;
                    }
                }
            }
            if (!illegal && requiredacceptrecrules.size() == 0 && requiredacceptnonrecrules.size() == 0) {
                returnval = true;
            }
        }

        return returnval;
    }

    private boolean isAllowedCAAdministratorRule(AccessRuleData ar) {
        boolean returnval = false;

        if (ar.getAccessRuleName().equals(StandardRules.CAACCESSBASE.resource()) && ar.getInternalState() == AccessRuleState.RULE_ACCEPT && ar.getRecursive()) {
            returnval = true;
        }

        if (ar.getAccessRuleName().startsWith(StandardRules.CAACCESS.resource()) && ar.getInternalState() == AccessRuleState.RULE_ACCEPT && !ar.getRecursive()) {
            returnval = true;
        }

        if (ar.getAccessRuleName().startsWith(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS) && ar.getInternalState() == AccessRuleState.RULE_ACCEPT) {
            returnval = true;
        }

        if (ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWLOG) && ar.getInternalState() == AccessRuleState.RULE_ACCEPT && ar.getRecursive()) {
            returnval = true;
        }

        return returnval;
    }

    private boolean isRAAdministrator(Collection<AccessRuleData> currentaccessrules) {
        boolean returnval = false;

        if (currentaccessrules.size() >= 4) {
            HashSet<String> requiredaccepnonrecrules = new HashSet<String>();
            requiredaccepnonrecrules.add(AccessRulesConstants.ROLE_ADMINISTRATOR);
            requiredaccepnonrecrules.add(AccessRulesConstants.REGULAR_CREATECERTIFICATE);
            requiredaccepnonrecrules.add(AccessRulesConstants.REGULAR_STORECERTIFICATE);
            requiredaccepnonrecrules.add(AccessRulesConstants.REGULAR_VIEWCERTIFICATE);

            boolean illegal = false;
            for(AccessRuleData ar : currentaccessrules) {                
                if (!isAllowedRAAdministratorRule(ar)) {
                    if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT && !ar.getRecursive() && requiredaccepnonrecrules.contains(ar.getAccessRuleName())) {
                        requiredaccepnonrecrules.remove(ar.getAccessRuleName());
                    } else {
                        illegal = true;
                        break;
                    }
                }
            }
            if (!illegal && requiredaccepnonrecrules.size() == 0) {
                returnval = true;
            }
        }

        return returnval;
    }

    private boolean isAllowedRAAdministratorRule(AccessRuleData ar) {
        boolean returnval = false;

        if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT) {
            if (ar.getAccessRuleName().equals(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS)) {
                returnval = true;
            }
            if (ar.getRecursive()) {
                if (ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWLOG)) {
                    returnval = true;
                }
                if (ar.getAccessRuleName().equals(AccessRulesConstants.ENDENTITYPROFILEBASE) || ar.getAccessRuleName().equals(StandardRules.CAACCESSBASE.resource())) {
                    returnval = true;
                }
            } else {
                if (ar.getAccessRuleName().startsWith(AccessRulesConstants.REGULAR_RAFUNCTIONALITY + "/")
                        && !ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES)) {
                    returnval = true;
                }
                if (ar.getAccessRuleName().startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                    returnval = true;
                }
                if (ar.getAccessRuleName().startsWith(StandardRules.CAACCESS.resource())) {
                    returnval = true;
                }
            }
        }
        return returnval;
    }

    private boolean isSupervisor(Collection<AccessRuleData> currentaccessrules) {
        boolean returnval = false;

        if (currentaccessrules.size() >= 2) {
            HashSet<String> requiredacceptrecrules = new HashSet<String>();
            requiredacceptrecrules.add(AccessRulesConstants.REGULAR_VIEWLOG);
            HashSet<String> requiredacceptnonrecrules = new HashSet<String>();
            requiredacceptnonrecrules.add(AccessRulesConstants.ROLE_ADMINISTRATOR);
            requiredacceptnonrecrules.add(AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
            
            boolean illegal = false;
            for(AccessRuleData ar : currentaccessrules) {    
                if (!isAllowedSupervisorRule(ar)) {
                    if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT && ar.getRecursive() && requiredacceptrecrules.contains(ar.getAccessRuleName())) {
                        requiredacceptrecrules.remove(ar.getAccessRuleName());
                    } else {
                        if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT && !ar.getRecursive() && requiredacceptnonrecrules.contains(ar.getAccessRuleName())) {
                            requiredacceptnonrecrules.remove(ar.getAccessRuleName());
                        } else {
                            illegal = true;
                            break;
                        }
                    }
                }
            }
            if (!illegal && requiredacceptrecrules.size() == 0 && requiredacceptnonrecrules.size() == 0) {
                returnval = true;
            }

        }

        return returnval;
    }

    private boolean isAllowedSupervisorRule(AccessRuleData ar) {
        boolean returnval = false;

        if (ar.getInternalState() == AccessRuleState.RULE_ACCEPT) {
            if (ar.getRecursive()) {
                if (ar.getAccessRuleName().equals(AccessRulesConstants.ENDENTITYPROFILEBASE) || ar.getAccessRuleName().equals(StandardRules.CAACCESSBASE.resource())) {
                    returnval = true;
                }
            } else {
                if (ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWENDENTITY)
                        || ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY)
                        || ar.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
                    returnval = true;
                }
                if (ar.getAccessRuleName().startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
                    returnval = true;
                }
                if (ar.getAccessRuleName().startsWith(StandardRules.CAACCESS.resource())) {
                    returnval = true;
                }
            }
        }
        return returnval;
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
                        if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.VIEW_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEW;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.HISTORY_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEWHISTORY;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.HARDTOKEN_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.CREATE_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_CREATE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.DELETE_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_DELETE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.EDIT_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_EDIT;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.REVOKE_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_REVOKE;
                        } else if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.KEYRECOVERY_RIGHTS)) {
                            currentval += BasicAccessRuleSet.ENDENTITY_KEYRECOVER;
                        }
                        if (accessRule.getAccessRuleName().endsWith(AccessRulesConstants.APPROVAL_RIGHTS)) {
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
                            if (accessRule.getAccessRuleName().equals(AccessRulesConstants.REGULAR_VIEWLOG)) {
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

        Iterator<Integer> eriter = endentityrules.keySet().iterator();
        while (eriter.hasNext()) {
            Integer next = eriter.next();
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
