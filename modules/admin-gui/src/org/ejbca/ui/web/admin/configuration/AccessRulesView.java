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

package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import org.cesecore.authorization.rules.AccessRuleData;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * A class used as a help class for displaying access rules
 * 

 * @version $Id$
 */
public class AccessRulesView implements Serializable {

    private static final long serialVersionUID = -3783242205091345836L;

    private ArrayList<AccessRuleData> rolebasedaccessrules;
    private ArrayList<AccessRuleData> regularaccessrules;
    private ArrayList<AccessRuleData> endentityprofileaccessrules;
    private ArrayList<AccessRuleData> userdatasourceaccessrules;
    private ArrayList<AccessRuleData> caaccessrules;

    /**
     * Creates an AccessRulesView and sorts the access rules into their appropriate sets.
     */
    public AccessRulesView(Collection<AccessRuleData> accessrules) {
        this.rolebasedaccessrules = new ArrayList<AccessRuleData>();
        this.regularaccessrules = new ArrayList<AccessRuleData>();
        this.endentityprofileaccessrules = new ArrayList<AccessRuleData>();
        this.caaccessrules = new ArrayList<AccessRuleData>();
        this.userdatasourceaccessrules = new ArrayList<AccessRuleData>();

        for(AccessRuleData accessrule : accessrules) {  
            boolean regular = true;

            // Check if rule is a role based one
            for (String roleConstant : AccessRulesConstants.ROLEACCESSRULES) {
                if (accessrule.getAccessRuleName().equals(roleConstant)) {
                    this.rolebasedaccessrules.add(accessrule);
                    regular = false;
                }
            }

            // Check if rule is end entity profile access rule
            if (accessrule.getAccessRuleName().startsWith("/endentityprofilesrules")) {
                this.endentityprofileaccessrules.add(accessrule);
                regular = false;
            }

            // Check if rule is CA access rule
            if (accessrule.getAccessRuleName().startsWith(AccessRulesConstants.CAPREFIX) || accessrule.getAccessRuleName().equals(AccessRulesConstants.CABASE)) {
                this.caaccessrules.add(accessrule);
                regular = false;
            }

            // Check if rule is end entity profile access rule
            if (accessrule.getAccessRuleName().startsWith(AccessRulesConstants.USERDATASOURCEBASE)) {
                this.userdatasourceaccessrules.add(accessrule);
                regular = false;
            }

            // Otherwise it's a regular accessrule.
            if (regular) {
                this.regularaccessrules.add(accessrule);
            }
        }

        Collections.sort(this.rolebasedaccessrules);
        Collections.sort(this.regularaccessrules);
        Collections.sort(this.endentityprofileaccessrules);
        Collections.sort(this.caaccessrules);
        Collections.sort(this.userdatasourceaccessrules);

    }

    /**
     * Method that returns all role based access rules, sorted.
     */
    public Collection<AccessRuleData> getRoleBasedAccessRules() {
        return this.rolebasedaccessrules;
    }

    /**
     * Method that returns all regular access rules, sorted.
     */
    public Collection<AccessRuleData> getRegularAccessRules() {
        return this.regularaccessrules;
    }

    /**
     * Method that returns all end entity profile access rules, sorted.
     */
    public Collection<AccessRuleData> getEndEntityProfileAccessRules() {
        return this.endentityprofileaccessrules;
    }

    /**
     * Method that returns all CA access rules, sorted.
     */
    public Collection<AccessRuleData> getCAAccessRules() {
        return this.caaccessrules;
    }

    /**
     * Method that returns all User Data Source access rules, sorted.
     */
    public Collection<AccessRuleData> getUserDataSourceAccessRules() {
        return this.userdatasourceaccessrules;
    }

}
