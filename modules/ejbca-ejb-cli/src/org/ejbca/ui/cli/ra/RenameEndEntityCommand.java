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
package org.ejbca.ui.cli.ra;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI command for renaming an end entity.
 * 
 * @version $Id$
 */
public class RenameEndEntityCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(RenameEndEntityCommand.class);

    private static final String SUBCOMMAND = "renameendentity";
    private static final String USERNAME_CURRENT_KEY = "--current";
    private static final String USERNAME_NEW_KEY = "--new";

    {
        registerParameter(new Parameter(USERNAME_CURRENT_KEY, "Current username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Current username for the end entity."));
        registerParameter(new Parameter(USERNAME_NEW_KEY, "New username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New username for the end entity."));
    }

    @Override
    public String getMainCommand() {
        return SUBCOMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String currentUsername = parameters.get(USERNAME_CURRENT_KEY);
        final String newUsername = parameters.get(USERNAME_NEW_KEY);
        try {
            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).renameEndEntity(getAuthenticationToken(), currentUsername, newUsername)) {
                getLogger().info("End entity '" + currentUsername + "' has been renamed to '" + newUsername + "'");
                return CommandResult.SUCCESS;
            } else {
                getLogger().error("End entity '" + currentUsername + "' could not be found.");
            }
        } catch (EndEntityExistsException e) {
            getLogger().error("The new username is already in use by another end entity.");
        } catch (AuthorizationDeniedException e) {
            getLogger().error(e.getMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Renames an end entity";
    }

    @Override
    public String getFullHelpText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription()).append("\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
