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

package org.ejbca.ui.cli.admins;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.roles.RoleData;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes an access rule
 */
public class AdminsChangeRuleCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "changerule";
    }

    public String getDescription() {
        return "Changes an access rule";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        String cliUserName = "username";
        String cliPassword = "passwordhash";
        AuthenticationSubject subject = getAuthenticationSubject(cliUserName, cliPassword);
        
        try {
            if (args.length < 5) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of group> <access rule> <rule> <recursive>");
                Collection<RoleData> adminGroups = ejb.getComplexAccessControlSession().getAllRolesAuthorizedToEdit(getAdmin(subject));
                Collections.sort((List<RoleData>) adminGroups);
                String availableGroups = "";
                for (RoleData adminGroup : adminGroups) {
                    availableGroups += (availableGroups.length() == 0 ? "" : ", ") + "\"" + adminGroup.getRoleName() + "\"";
                }
                getLogger().info("Available Admin groups: " + availableGroups);
                getLogger().info("Available access rules:");
                GlobalConfiguration globalConfiguration = ejb.getGlobalConfigurationSession().getCachedGlobalConfiguration(getAdmin(subject));

                Collection<String> authorizedAvailableAccessRules = ejb.getComplexAccessControlSession().getAuthorizedAvailableAccessRules(
                        getAdmin(subject), globalConfiguration.getEnableEndEntityProfileLimitations(), globalConfiguration.getIssueHardwareTokens(),
                        globalConfiguration.getEnableKeyRecovery(), ejb.getEndEntityProfileSession().getAuthorizedEndEntityProfileIds(getAdmin(subject)),
                        ejb.getUserDataSourceSession().getAuthorizedUserDataSourceIds(getAdmin(subject), true),
                        EjbcaConfiguration.getCustomAvailableAccessRules());

                for (String current : authorizedAvailableAccessRules) {
                    getLogger().info(" " + getParsedAccessRule(getAdmin(subject), current));
                }
                String availableRules = "";
                for (AccessRuleState current : AccessRuleState.values()) {
                    availableRules += (availableRules.length() == 0 ? "" : ", ") + current.getName();
                }
                getLogger().info("Available rules: " + availableRules);
                getLogger().info("Recursive is one of: TRUE, FALSE");
                return;
            }
            String groupName = args[1];
            RoleData role = ejb.getRoleAccessSession().findRole(groupName);
            if (role == null) {
                getLogger().error("No such group \"" + groupName + "\" .");
                return;
            }
            String accessRule = getOriginalAccessRule(getAdmin(subject), args[2]);
            GlobalConfiguration globalConfiguration = ejb.getGlobalConfigurationSession().getCachedGlobalConfiguration(getAdmin(subject));
            Collection<String> authorizedAvailableAccessRules = ejb.getComplexAccessControlSession().getAuthorizedAvailableAccessRules(getAdmin(subject),
                    globalConfiguration.getEnableEndEntityProfileLimitations(), globalConfiguration.getIssueHardwareTokens(),
                    globalConfiguration.getEnableKeyRecovery(), ejb.getEndEntityProfileSession().getAuthorizedEndEntityProfileIds(getAdmin(subject)),
                    ejb.getUserDataSourceSession().getAuthorizedUserDataSourceIds(getAdmin(subject), true),
                    EjbcaConfiguration.getCustomAvailableAccessRules());

            if (!authorizedAvailableAccessRules.contains(accessRule)) {
                getLogger().error("Accessrule \"" + accessRule + "\" is not available.");
                return;
            }
            AccessRuleState rule = AccessRuleState.matchName(args[3]);
            if (rule == null) {
                getLogger().error("No such rule \"" + args[3] + "\".");
                return;
            }
            boolean recursive = "TRUE".equalsIgnoreCase(args[4]);
            List<String> accessRuleStrings = new ArrayList<String>();

            accessRuleStrings.add(accessRule);
            if (rule == AccessRuleState.RULE_NOTUSED) {
                ejb.getRoleManagementSession().removeAccessRulesFromRole(getAdmin(subject), role, accessRuleStrings);
            } else {
                ejb.getRoleManagementSession().removeAccessRulesFromRole(getAdmin(subject), role, accessRuleStrings);
                AccessRuleData accessRuleObject = new AccessRuleData(role.getRoleName(), accessRule, rule, recursive);
                Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
                accessRules.add(accessRuleObject);
                ejb.getRoleManagementSession().addAccessRulesToRole(getAdmin(subject), role, accessRules);
            }
        } catch (Exception e) {
            getLogger().error("", e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
