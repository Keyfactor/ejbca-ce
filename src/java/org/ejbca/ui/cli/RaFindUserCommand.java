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

import se.anatom.ejbca.common.UserDataVO;




/**
 * Find details of a user in the database.
 *
 * @version $Id: RaFindUserCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class RaFindUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaFindUserCommand
     *
     * @param args command line arguments
     */
    public RaFindUserCommand(String[] args) {
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
            if (args.length < 2) {
                getOutputStream().println("Usage: RA finduser <username>");

                return;
            }

            String username = args[1];

            try {
                UserDataVO data = getAdminSession().findUser(administrator, username);

                if (data != null) {
                    getOutputStream().println("Found user:");
                    getOutputStream().println("username=" + data.getUsername());
                    getOutputStream().println("password=" + data.getPassword());
                    getOutputStream().println("dn: \"" + data.getDN() + "\"");
                    getOutputStream().println("email=" + data.getEmail());
                    getOutputStream().println("status=" + data.getStatus());
                    getOutputStream().println("type=" + data.getType());
                    getOutputStream().println("token type=" + data.getTokenType());
                    getOutputStream().println("end entity profile id=" + data.getEndEntityProfileId());
                    getOutputStream().println("certificate entity profile id=" +
                        data.getCertificateProfileId());
                    getOutputStream().println("hard token issuer id=" + data.getHardTokenIssuerId());
                    getOutputStream().println("created=" + data.getTimeCreated());
                    getOutputStream().println("modified=" + data.getTimeModified());
                } else {
                    getOutputStream().println("User '" + username + "' does not exist.");
                }
            } catch (AuthorizationDeniedException e) {
                getOutputStream().println("Error : Not authorized to view user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
