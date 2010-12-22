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

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Deletes a user from the database.
 *
 * @version $Id$
 */
public class RaDelUserCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "deluser"; }
	public String getDescription() { return "Deletes a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		// Get and remove switches
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean force = argsList.remove("-force");
		args = argsList.toArray(new String[0]);
		// Parse the rest of the arguments
        if (args.length < 2) {
			getLogger().info("Description: " + getDescription());
			getLogger().info("Usage: " + getCommand() + " [-force] <username>");
			getLogger().info(" -force   Don't ask if the user has been revoked.");
			return;
        }
        try {
            String username = args[1];
            int inp = 121;
            if (!force) {
                getLogger().info("Have you revoked the user [y/N]? ");
                inp = System.in.read();
            }
            if ((inp == 121) || (inp == 89)) {
                try {
                    ejb.getUserAdminSession().deleteUser(getAdmin(), username);
                    getLogger().info("Deleted user " + username);
                } catch (AuthorizationDeniedException e) {
                	getLogger().error("Not authorized to remove user.");
                }
            } else {
            	getLogger().info("Delete aborted!");
            	getLogger().info("Please run '" + new RaRevokeUserCommand().getMainCommand() + " " + new RaRevokeUserCommand().getSubCommand() + " " + username + "'.");
            }
        } catch (NotFoundException e) {
        	getLogger().error("No such user.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
