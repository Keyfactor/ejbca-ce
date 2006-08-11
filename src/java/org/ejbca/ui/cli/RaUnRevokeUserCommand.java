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
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;





/**
 * Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id: RaUnRevokeUserCommand.java,v 1.2 2006-08-11 04:17:43 herrvendil Exp $
 */
public class RaUnRevokeUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaRevokeUserCommand
     *
     * @param args command line arguments
     */
    public RaUnRevokeUserCommand(String[] args) {
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
                getOutputStream().println("Usage: RA unrevokeuser <username>");
                getOutputStream().println("A users certificate can unly be unrevoked if the revocation reason is certificate_hold.");
                return;
            }

            String username = args[1];

            UserDataVO data = getAdminSession().findUser(administrator, username);
            getOutputStream().println("Found user:");
            getOutputStream().println("username=" + data.getUsername());
            getOutputStream().println("dn=\"" + data.getDN() + "\"");
            getOutputStream().println("Old status=" + data.getStatus());
            getAdminSession().setUserStatus(administrator, username,
            		UserDataConstants.STATUS_GENERATED,false);
            getOutputStream().println("New status=" + UserDataConstants.STATUS_GENERATED);

            // Revoke users certificates
            try {
            	getAdminSession().revokeUser(administrator, username, RevokedCertInfo.NOT_REVOKED);
            } catch (AuthorizationDeniedException e) {
            	getOutputStream().println("Error : Not authorized to un-revoke user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
