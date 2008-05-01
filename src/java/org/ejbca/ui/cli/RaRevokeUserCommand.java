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

import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.UserDataVO;





/**
 * Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id$
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
                // Revoke users certificates
                try {
                    getAdminSession().revokeUser(administrator, username, reason);
                    data = getAdminSession().findUser(administrator, username);
                    getOutputStream().println("New status=" + data.getStatus());
                } catch (AuthorizationDeniedException e) {
                    getOutputStream().println("Error : Not authorized to revoke user.");
                } catch (ApprovalException e) {
                	getOutputStream().println("Error : Revocation already requested.");
                } catch (WaitingForApprovalException e) {
                	getOutputStream().println("Revocation request has been sent for approval.");
                } catch (AlreadyRevokedException e) {
                	getOutputStream().println("Error: User is already revoked.");
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
