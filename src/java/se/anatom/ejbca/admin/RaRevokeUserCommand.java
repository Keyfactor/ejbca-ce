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
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.ra.UserDataConstants;


/**
 * Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id: RaRevokeUserCommand.java,v 1.16 2005-04-29 08:15:46 anatom Exp $
 */
public class RaRevokeUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaRevokeUserCommand
     *
     * @param args command line arguments
     */
    public RaRevokeUserCommand(String[] args) {
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
                getOutputStream().println("Usage: RA revokeuser <username> <reason>");
                getOutputStream().println(
                    "Reason: unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3), superseded(4), cessationOfOperation(5), certficateHold(6), removeFromCRL(8),privilegeWithdrawn(9),aACompromise(10)");
                getOutputStream().println("Normal reason is 0");

                return;
            }

            String username = args[1];
            int reason = Integer.parseInt(args[2]);

            if ((reason == 7) || (reason < 0) || (reason > 10)) {
                getOutputStream().println("Error : Reason must be an integer between 0 and 10 except 7.");
            } else {
                UserDataVO data = getAdminSession().findUser(administrator, username);
                getOutputStream().println("Found user:");
                getOutputStream().println("username=" + data.getUsername());
                getOutputStream().println("dn=\"" + data.getDN() + "\"");
                getOutputStream().println("Old status=" + data.getStatus());
                getAdminSession().setUserStatus(administrator, username,
                        UserDataConstants.STATUS_REVOKED);
                getOutputStream().println("New status=" + UserDataConstants.STATUS_REVOKED);

                // Revoke users certificates
                try {
                    getAdminSession().revokeUser(administrator, username, reason);
                } catch (AuthorizationDeniedException e) {
                    getOutputStream().println("Error : Not authorized to revoke user.");
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
