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

import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
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
        String roleName = parameters.get(ROLE_NAME_KEY);
        try {
            final Role role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getRole(getAuthenticationToken(), null, roleName);
            if (role == null) {
            	getLogger().error("ERROR: No such role '" + roleName + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            for (final Entry<String,Boolean> entry : AccessRulesHelper.getAsListSortedByKey(role.getAccessRules())) {
            	getLogger().info(super.getResourceToResourceNameMap().get(entry.getKey()) + " " + (entry.getValue() ? "ALLOW" : "DENY"));
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
        	getLogger().error(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
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
