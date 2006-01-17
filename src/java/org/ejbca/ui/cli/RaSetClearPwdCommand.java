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
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;



/**
 * Set the clear text password for a user in the database.  Clear text passwords are used for batch
 * generation of keystores (pkcs12/pem).
 *
 * @version $Id: RaSetClearPwdCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class RaSetClearPwdCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetClearPwdCommand
     *
     * @param args command line arguments
     */
    public RaSetClearPwdCommand(String[] args) {
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
                getOutputStream().println("Usage: RA setclearpwd <username> <password>");

                return;
            }

            String username = args[1];
            String password = args[2];
            getOutputStream().println("Setting clear text password " + password + " for user " + username);

            try {
                getAdminSession().setClearTextPassword(administrator, username, password);
            } catch (AuthorizationDeniedException e) {
                getOutputStream().println("Error : Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
                getOutputStream().println("Error : Given userdata doesn't fullfill end entity profile. : " +
                    e.getMessage());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
