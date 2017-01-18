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
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Lists access rules for a role
 * 
 * @version $Id$
 */
public class ListRulesCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(ListRulesCommand.class);

    private static final String ROLE_NAME_KEY = "--role";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to list rules of."));
    }

    @Override
    public String getMainCommand() {
        return "listrules";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String groupName = parameters.get(ROLE_NAME_KEY);
        AdminGroupData role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class).findRole(groupName);
        if (role == null) {
            getLogger().error("ERROR: No such role \"" + groupName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        List<AccessRuleData> list = new ArrayList<AccessRuleData>(role.getAccessRules().values());
        Collections.sort(list);
        boolean errorCaught = false;
        for (AccessRuleData accessRule : list) {
            try {
                getLogger().info(
                        getParsedAccessRule(getAuthenticationToken(), accessRule.getAccessRuleName()) + " " + accessRule.getInternalState().getName()
                                + " " + (accessRule.getRecursive() ? "RECURSIVE" : ""));
            } catch (CADoesntExistsException e) {
                log.error("ERROR: Attempted to retireve rule for CA that doesn't exit: " + e.getMessage());
                errorCaught = true;
            } catch (AuthorizationDeniedException e) {
                log.error("ERROR: CLI user not authorized to rule " + accessRule);
                errorCaught = true;
            }
        }
        if (errorCaught == true) {
            return CommandResult.FUNCTIONAL_FAILURE;
        } else {
            return CommandResult.SUCCESS;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Lists access rules for a role";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
