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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
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
 * Adds a new admin role
 * @version $Id$
 */
public class AddRoleCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(AddRoleCommand.class);

    private static final String NAME_KEY = "--role";

    {
        registerParameter(new Parameter(NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the new role."));
    }

    @Override
    public String getMainCommand() {
        return "addrole";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String roleName = parameters.get(NAME_KEY);
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).persistRole(getAuthenticationToken(), new Role(null, roleName));
            return CommandResult.SUCCESS;
        } catch (RoleExistsException e) {
            log.error("ERROR: Role of name " + roleName + " already exists.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: CLI user not authorized to add role.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Adds an administrative role.";
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
