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

package org.ejbca.ui.cli.ra;

import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Deletes an end entity from the database.
 * 
 * @version $Id$
 */
public class DeleteEndEntityCommand extends BaseRaCommand {

    private static final String OLD_COMMAND = "deluser";
    private static final String COMMAND = "delendentity";
    
    @Override
    public String getSubCommand() {
        return COMMAND;
    }
    
    @Override
    public String[] getSubCommandAliases() {
        return new String[]{OLD_COMMAND};
    }

    @Override
    public String getDescription() {
        return "Deletes an and entity";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        // Get and remove switches
        List<String> argsList = CliTools.getAsModifyableList(args);
        boolean force = argsList.remove("-force");
        args = argsList.toArray(new String[argsList.size()]);
        // Parse the rest of the arguments
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " [-force] <username>");
            getLogger().info(" -force   Don't ask if the end entity has been revoked.");
            return;
        }
        try {
            String username = args[1];
            int inp = 121;
            if (!force) {
                getLogger().info("Have you revoked the end entity [y/N]? ");
                inp = System.in.read();
            }
            if ((inp == 121) || (inp == 89)) {
                try {
                    ejb.getRemoteSession(EndEntityManagementSessionRemote.class).deleteUser(getAuthenticationToken(cliUserName, cliPassword), username);
                    getLogger().info("Deleted end entity with username: " + username);
                } catch (AuthorizationDeniedException e) {
                    getLogger().error("Not authorized to remove end entity.");
                }
            } else {
                getLogger().info("Delete aborted!");
                getLogger().info(
                        "Please run '" + new RevokeEndEntityCommand().getMainCommand() + " " + new RevokeEndEntityCommand().getSubCommand() + " "
                                + username + "'.");
            }
        } catch (NotFoundException e) {
            getLogger().error("No such end entity.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }


}
