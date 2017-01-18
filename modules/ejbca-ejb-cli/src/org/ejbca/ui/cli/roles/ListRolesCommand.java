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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Lists admin roles
 * @version $Id$
 */
public class ListRolesCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(ListRolesCommand.class);

    @Override
    public String getMainCommand() {
        return "listroles";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        Collection<AdminGroupData> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).getAllRolesAuthorizedToEdit(
                getAuthenticationToken());
        Collections.sort((List<AdminGroupData>) roles);
        for (AdminGroupData role : roles) {
            int numberOfAdmins = role.getAccessUsers().size();
            getLogger().info(role.getRoleName() + " (" + numberOfAdmins + " admin" + (numberOfAdmins == 1 ? "" : "s") + ")");
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Lists admin roles";
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
