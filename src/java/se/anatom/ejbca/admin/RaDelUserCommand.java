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


/**
 * Deletes a user from the database.
 *
 * @version $Id: RaDelUserCommand.java,v 1.8 2004-04-16 07:38:57 anatom Exp $
 */
public class RaDelUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaDelUserCommand
     *
     * @param args command line arguments
     */
    public RaDelUserCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
            throw new IllegalAdminCommandException("Usage: RA deluser <username>");
        }

        try {
            String username = args[1];
            System.out.print("Have you revoked the user [y/N]? ");

            int inp = System.in.read();

            if ((inp == 121) || (inp == 89)) {
                try {
                    getAdminSession().deleteUser(administrator, username);
                    System.out.println("Deleted user " + username);
                } catch (AuthorizationDeniedException e) {
                    System.out.println("Error : Not authorized to remove user.");
                }
            } else {
                System.out.println("Delete aborted!");
                System.out.println("Please run 'ra revokeuser " + username + "'.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
