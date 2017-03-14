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

package org.ejbca.ui.cli.roles;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
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
        final Role role;
        try {
            role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getRole(getAuthenticationToken(), null, roleName);
        } catch (AuthorizationDeniedException e1) {
            getLogger().error("Not authorized to role \"" + roleName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (role == null) {
            getLogger().error("No such role \"" + roleName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            final String resourceName = AccessRulesHelper.normalizeResource(parameters.get(RULE_KEY));
            final String resource = super.getResourceNameToResourceMap().get(resourceName);
            if (resource==null) {
                getLogger().error("ERROR: No resource with name '" + resourceName + "' is available.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            final AccessRuleState rule = AccessRuleState.matchName(parameters.get(STATE_KEY));
            if (rule == null) {
                getLogger().error("ERROR: No such state \"" + parameters.get(STATE_KEY) + "\".");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            if (parameters.containsKey(RECURSIVE_KEY)) {
                // Be nice and log, but don't fail existing scripts depending on this command
                getLogger().warn("Setting " + RECURSIVE_KEY + " is not needed from EJBCA 6.8.0, since all rules are always recursive.");
            }

            if (rule == AccessRuleState.RULE_NOTUSED) {
                if (role.getAccessRules().remove(resource)==null) {
                    getLogger().info("No rule for resource '" + resourceName + "' found.");
                }
            } else if (rule == AccessRuleState.RULE_ACCEPT) {
                if (role.getAccessRules().put(resource, Role.STATE_ALLOW)==null) {
                    getLogger().info("Added accept rule for resource '" + resourceName + "'.");
                } else {
                    getLogger().info("Replaces existing access rule with allow rule for resource '" + resourceName + "'.");
                }
            } else {
                if (role.getAccessRules().put(resource, Role.STATE_DENY)==null) {
                    getLogger().info("Added deny rule for resource '" + resourceName + "'.");
                } else {
                    getLogger().info("Replaces existing access rule with deny rule for resource '" + resourceName + "'.");
                }
            }
            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).persistRole(getAuthenticationToken(), role);
            } catch (RoleExistsException e) {
                getLogger().error("ERROR: Unable to save changes: " + e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to edit rule " + parameters.get(RULE_KEY));
            return CommandResult.AUTHORIZATION_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Changes an access rule";
    }

    @Override
    public String getFullHelpText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        final List<Role> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getAuthorizedRoles(getAuthenticationToken());
        Collections.sort(roles);
        final StringBuilder availableRoles = new StringBuilder();
        for (final Role role : roles) {
            availableRoles.append((availableRoles.length() == 0 ? "" : ", ") + "\"" + role.getRoleNameFull() + "\"");
        }
        sb.append("Available roles: " + availableRoles + "\n");
        final List<String> resourceNames = new ArrayList<>(super.getResourceNameToResourceMap().keySet());
        Collections.sort(resourceNames);
        final StringBuilder availableRules = new StringBuilder();
        for (final String resourceName : resourceNames) {
            availableRules.append("          " + resourceName + "\n");
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
