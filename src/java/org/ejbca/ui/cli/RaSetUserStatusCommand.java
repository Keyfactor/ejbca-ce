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
 
package org.ejbca.ui.cli;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;


/**
 * Changes status for a user in the database, status is defined in
 * org.ejbca.core.ejb.ra.UserDataLocal.
 *
 * @version $Id: RaSetUserStatusCommand.java,v 1.2 2006-08-11 04:17:43 herrvendil Exp $
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class RaSetUserStatusCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetUserStatusCommand
     *
     * @param args command line arguments
     */
    public RaSetUserStatusCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 3) {
                getOutputStream().println("Usage: RA setuserstatus <username> <status>");
                getOutputStream().println(
                    "Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");

                return;
            }

            String username = args[1];
            int status = Integer.parseInt(args[2]);

            try {
                getAdminSession().setUserStatus(administrator, username, status,true);
                getOutputStream().println("New status for user " + username + " is " + status);
            } catch (AuthorizationDeniedException e) {
                getOutputStream().println("Error : Not authorized to change userdata.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
