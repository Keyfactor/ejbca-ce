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

import javax.ejb.EJB;

import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes status for a user in the database, status is defined in
 * org.ejbca.core.ejb.ra.UserDataLocal.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class RaSetUserStatusCommand extends BaseRaAdminCommand {

    @EJB
    private UserAdminSessionRemote userAdminSession;
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "setuserstatus"; }
	public String getDescription() { return "Change status for a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 3) {
    			getLogger().info("Description: " + getDescription());
            	getLogger().info("Usage: " + getCommand() + " <username> <status>");
            	getLogger().info(" Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                return;
            }
            String username = args[1];
            int status = Integer.parseInt(args[2]);
            try {
                userAdminSession.setUserStatus(getAdmin(), username, status);
                getLogger().info("New status for user " + username + " is " + status);
            } catch (AuthorizationDeniedException e) {
            	getLogger().error("Not authorized to change userdata.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
