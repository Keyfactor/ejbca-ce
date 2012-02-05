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

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSession;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
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
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 5) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of role> <access rule> <rule> <recursive>");
                Collection<RoleData> roles = ejb.getRemoteSession(RoleManagementSessionRemote.class).getAllRolesAuthorizedToEdit(getAdmin(cliUserName, cliPassword));
                Collections.sort((List<RoleData>) roles);
                String availableRoles = "";
                for (RoleData role : roles) {
                    availableRoles += (availableRoles.length() == 0 ? "" : ", ") + "\"" + role.getRoleName() + "\"";
                }
                getLogger().info("Available roles: " + availableRoles);
                getLogger().info("Available access rules:");
                GlobalConfiguration globalConfiguration = ejb.getRemoteSession(GlobalConfigurationSessionRemote.class).getCachedGlobalConfiguration();

                Collection<String> authorizedAvailableAccessRules = ejb.getRemoteSession(ComplexAccessControlSessionRemote.class).getAuthorizedAvailableAccessRules(
                        getAdmin(cliUserName, cliPassword), globalConfiguration.getEnableEndEntityProfileLimitations(), globalConfiguration.getIssueHardwareTokens(),
                        globalConfiguration.getEnableKeyRecovery(), ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(getAdmin(cliUserName, cliPassword)),
                        ejb.getRemoteSession(UserDataSourceSessionRemote.class).getAuthorizedUserDataSourceIds(getAdmin(cliUserName, cliPassword), true),
                        EjbcaConfiguration.getCustomAvailableAccessRules());

                for (String current : authorizedAvailableAccessRules) {
                    getLogger().info(" " + getParsedAccessRule(getAdmin(cliUserName, cliPassword), current));
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
            RoleData role = ejb.getRemoteSession(RoleAccessSession.class).findRole(groupName);
            if (role == null) {
                getLogger().error("No such role \"" + groupName + "\".");
                return;
            }
            String accessRule = getOriginalAccessRule(getAdmin(cliUserName, cliPassword), args[2]);
            GlobalConfiguration globalConfiguration = ejb.getRemoteSession(GlobalConfigurationSessionRemote.class).getCachedGlobalConfiguration();
            Collection<String> authorizedAvailableAccessRules = ejb.getRemoteSession(ComplexAccessControlSessionRemote.class).getAuthorizedAvailableAccessRules(getAdmin(cliUserName, cliPassword),
                    globalConfiguration.getEnableEndEntityProfileLimitations(), globalConfiguration.getIssueHardwareTokens(),
                    globalConfiguration.getEnableKeyRecovery(), ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(getAdmin(cliUserName, cliPassword)),
                    ejb.getRemoteSession(UserDataSourceSessionRemote.class).getAuthorizedUserDataSourceIds(getAdmin(cliUserName, cliPassword), true),
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
                ejb.getRemoteSession(RoleManagementSessionRemote.class).removeAccessRulesFromRole(getAdmin(cliUserName, cliPassword), role, accessRuleStrings);
            } else {
                ejb.getRemoteSession(RoleManagementSessionRemote.class).removeAccessRulesFromRole(getAdmin(cliUserName, cliPassword), role, accessRuleStrings);
                AccessRuleData accessRuleObject = new AccessRuleData(role.getRoleName(), accessRule, rule, recursive);
                Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
                accessRules.add(accessRuleObject);
                ejb.getRemoteSession(RoleManagementSessionRemote.class).addAccessRulesToRole(getAdmin(cliUserName, cliPassword), role, accessRules);
            }
        } catch (Exception e) {
            getLogger().error("", e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
