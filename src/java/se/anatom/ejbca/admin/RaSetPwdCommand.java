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
 
package se.anatom.ejbca.admin;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;


/**
 * Set the (hashed) password for a user in the database.
 *
 * @version $Id: RaSetPwdCommand.java,v 1.9 2004-04-16 07:38:57 anatom Exp $
 */
public class RaSetPwdCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaSetPwdCommand
     *
     * @param args command line arguments
     */
    public RaSetPwdCommand(String[] args) {
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
                System.out.println("Usage: RA setpwd <username> <password>");

                return;
            }

            String username = args[1];
            String password = args[2];
            System.out.println("Setting password (hashed only) " + password + " for user " +
                username);

            try {
                getAdminSession().setPassword(administrator, username, password);
            } catch (AuthorizationDeniedException e) {
                System.out.println("Error : Not authorized to change userdata.");
            } catch (UserDoesntFullfillEndEntityProfile e) {
                System.out.println("Error : Given userdata doesn't fullfill profile.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
