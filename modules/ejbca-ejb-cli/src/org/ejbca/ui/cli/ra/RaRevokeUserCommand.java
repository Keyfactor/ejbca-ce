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

import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id$
 */
public class RaRevokeUserCommand extends BaseRaAdminCommand {

    private UserAdminSessionRemote userAdminSession = ejb.getUserAdminSession();
    
	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "revokeuser"; }
	public String getDescription() { return "Revokes a user and all certificates for a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 3) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <username> <reason>");
                getLogger().info(" Reason: unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3)," +
                		" superseded(4), cessationOfOperation(5), certficateHold(6), removeFromCRL(8),privilegeWithdrawn(9),aACompromise(10)");
                getLogger().info(" Normal reason is 0");
                return;
            }
            String username = args[1];
            int reason = Integer.parseInt(args[2]);
            if ((reason == 7) || (reason < 0) || (reason > 10)) {
            	getLogger().error("Reason must be an integer between 0 and 10 except 7.");
            } else {
                UserDataVO data = userAdminSession.findUser(getAdmin(), username);
                if (data==null) {
                	getLogger().error("User not found.");
                	return;
                }
                getLogger().info("Found user:");
                getLogger().info("username=" + data.getUsername());
                getLogger().info("dn=\"" + data.getDN() + "\"");
                getLogger().info("Old status=" + data.getStatus());
                // Revoke users certificates
                try {
                    userAdminSession.revokeUser(getAdmin(), username, reason);
                    data = userAdminSession.findUser(getAdmin(), username);
                    getLogger().info("New status=" + data.getStatus());
                } catch (AuthorizationDeniedException e) {
                	getLogger().error("Not authorized to revoke user.");
                } catch (ApprovalException e) {
                	getLogger().error("Revocation already requested.");
                } catch (WaitingForApprovalException e) {
                	getLogger().info("Revocation request has been sent for approval.");
                } catch (AlreadyRevokedException e) {
                	getLogger().error("User is already revoked.");
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
