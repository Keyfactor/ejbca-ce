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

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Deletes an end entity from the database.
 * 
 * @version $Id$
 */
public class DeleteEndEntityCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(DeleteEndEntityCommand.class);

    private static final String OLD_COMMAND = "deluser";
    private static final String COMMAND = "delendentity";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    private static final String USERNAME_KEY = "--username";
    private static final String FORCE_KEY = "-force";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity to delete."));
        registerParameter(Parameter.createFlag(FORCE_KEY, "Don't ask if the end entity has been revoked."));
    }

    @Override
    public Set<String> getMainCommandAliases() {
        return ALIASES;
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        boolean force = parameters.containsKey(FORCE_KEY);

        try {
            String username = parameters.get(USERNAME_KEY);
            int inp = 121;
            if (!force) {
                getLogger().info("Have you revoked the end entity [y/N]? ");
                try {
                    inp = System.in.read();
                } catch (IOException e) {
                    throw new IllegalStateException("Could not read console input.");
                }
            }
            if ((inp == 121) || (inp == 89)) {
                try {
                    EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(), username);
                    getLogger().info("Deleted end entity with username: " + username);
                    return CommandResult.SUCCESS;
                } catch (AuthorizationDeniedException e) {
                    getLogger().error("ERROR: Not authorized to remove end entity.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (RemoveException e) {
                    getLogger().error("ERROR: User could not be removed. " + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            } else {
                getLogger().info("Deletion aborted!");
                getLogger().info(
                        "Please run '" + new RevokeEndEntityCommand().getMainCommand() + " " + new RevokeEndEntityCommand().getMainCommand() + " "
                                + username + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (NoSuchEndEntityException e) {
            getLogger().error("ERROR: No such end entity.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Deletes an end entity";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + ".\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }

}
