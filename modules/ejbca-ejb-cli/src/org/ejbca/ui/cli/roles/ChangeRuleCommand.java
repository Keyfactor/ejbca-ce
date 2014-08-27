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

package org.ejbca.ui.cli.roles;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.Configuration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes an access rule
 */
public class ChangeRuleCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(ChangeRuleCommand.class);

    private static final String NAME_KEY = "--name";
    private static final String RULE_KEY = "--rule";
    private static final String STATE_KEY = "--state";
    private static final String RECURSIVE_KEY = "-R";

    {
        registerParameter(new Parameter(NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the role to modify."));
        registerParameter(new Parameter(RULE_KEY, "Rule", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "The rule to change"));
        registerParameter(new Parameter(STATE_KEY, "Rule State", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The state of the rule."));
        registerParameter(Parameter.createFlag(RECURSIVE_KEY, "Set this switch if rule is to be recursive. Default is false."));
    }

    @Override
    public String getMainCommand() {
        return "changerule";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String roleName = parameters.get(NAME_KEY);
        RoleData role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName);
        if (role == null) {
            getLogger().error("No such role \"" + roleName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        String accessRule;
        try {
            try {
                accessRule = getOriginalAccessRule(getAuthenticationToken(), parameters.get(RULE_KEY));
            } catch (EndEntityProfileNotFoundException e) {
                getLogger().error(e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (CADoesntExistsException e) {
                getLogger().error(e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(
                    GlobalConfigurationSessionRemote.class).getCachedConfiguration(Configuration.GlobalConfigID);
            Map<String, Set<String>> authorizedAvailableAccessRules = EjbRemoteHelper.INSTANCE.getRemoteSession(ComplexAccessControlSessionRemote.class)
                    .getAuthorizedAvailableAccessRules(
                            getAuthenticationToken(),
                            globalConfiguration.getEnableEndEntityProfileLimitations(),
                            globalConfiguration.getIssueHardwareTokens(),
                            globalConfiguration.getEnableKeyRecovery(),
                            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                                    getAuthenticationToken()),
                            EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getAuthorizedUserDataSourceIds(
                                    getAuthenticationToken(), true), EjbcaConfiguration.getCustomAvailableAccessRules());
            Set<String> uncategorizedAuthorizedAccessRules = new HashSet<String>();
            for(Set<String> subset : authorizedAvailableAccessRules.values()) {
                uncategorizedAuthorizedAccessRules.addAll(subset);
            }
            if (!uncategorizedAuthorizedAccessRules.contains(accessRule)) {
                getLogger().error("ERROR: Accessrule \"" + accessRule + "\" is not available.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            AccessRuleState rule = AccessRuleState.matchName(parameters.get(STATE_KEY));
            if (rule == null) {
                getLogger().error("ERROR: No such state \"" + parameters.get(STATE_KEY) + "\".");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            boolean recursive = false;
            if (parameters.containsKey(RECURSIVE_KEY)) {
                if (rule == AccessRuleState.RULE_ACCEPT) {
                    recursive = true;
                } else {
                    getLogger().info("Setting " + RECURSIVE_KEY + " for DECLINE or UNUSED is redundant. DECLINE and UNUSED are always recursive.");
                }
            }

            List<String> accessRuleStrings = new ArrayList<String>();
            accessRuleStrings.add(accessRule);
            if (rule == AccessRuleState.RULE_NOTUSED) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).removeAccessRulesFromRole(getAuthenticationToken(),
                        role, accessRuleStrings);
            } else {
                EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).removeAccessRulesFromRole(getAuthenticationToken(),
                        role, accessRuleStrings);
                AccessRuleData accessRuleObject = new AccessRuleData(role.getRoleName(), accessRule, rule, recursive);
                Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
                accessRules.add(accessRuleObject);
                EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).addAccessRulesToRole(getAuthenticationToken(), role,
                        accessRules);
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to edit rule " + parameters.get(RULE_KEY));
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (RoleNotFoundException e) {
            throw new IllegalStateException("Previously found role could suddenly not be found.", e);
        }

    }

    @Override
    public String getCommandDescription() {
        return "Changes an access rule";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        Collection<RoleData> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).getAllRolesAuthorizedToEdit(
                getAuthenticationToken());
        Collections.sort((List<RoleData>) roles);
        StringBuilder availableRoles = new StringBuilder();
        for (RoleData role : roles) {
            availableRoles.append((availableRoles.length() == 0 ? "" : ", ") + "\"" + role.getRoleName() + "\"");
        }
        sb.append("Available roles: " + availableRoles + "\n");

        GlobalConfiguration globalConfiguration = (GlobalConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(
                GlobalConfigurationSessionRemote.class).getCachedConfiguration(Configuration.GlobalConfigID);

        Map<String, Set<String>> authorizedAvailableAccessRules = EjbRemoteHelper.INSTANCE.getRemoteSession(ComplexAccessControlSessionRemote.class)
                .getAuthorizedAvailableAccessRules(
                        getAuthenticationToken(),
                        globalConfiguration.getEnableEndEntityProfileLimitations(),
                        globalConfiguration.getIssueHardwareTokens(),
                        globalConfiguration.getEnableKeyRecovery(),
                        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                                getAuthenticationToken()),
                        EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getAuthorizedUserDataSourceIds(
                                getAuthenticationToken(), true), EjbcaConfiguration.getCustomAvailableAccessRules());

        StringBuilder availableRules = new StringBuilder();
        for(String category : authorizedAvailableAccessRules.keySet()) {
            availableRules.append("   " + category.toUpperCase() + ":\n");
            for (String current : authorizedAvailableAccessRules.get(category)) {
                try {
                    availableRules.append("      " + getParsedAccessRule(getAuthenticationToken(), current) + "\n");
                } catch (AuthorizationDeniedException e) {
                    log.error("ERROR: Rules exist for CAs(" + current + ") that CLI user is not authorized to.");
                } catch (CADoesntExistsException e) {
                    log.error("ERROR: Rules exist for CAs(" + current + ") that don't exist.");
                }
            }
        }
        sb.append("Available access rules: \n" + availableRules);
        StringBuilder availableRuleStates = new StringBuilder();
        for (AccessRuleState current : AccessRuleState.values()) {
            availableRuleStates.append((availableRuleStates.length() == 0 ? "" : ", ") + current.getName());
        }
        sb.append("Available access rule states: " + availableRuleStates + "\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
