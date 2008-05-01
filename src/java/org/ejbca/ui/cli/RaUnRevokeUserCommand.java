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

import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.UserDataVO;





/**
 * Revokes a user in the database, and also revokes all the users certificates.
 *
 * @version $Id$
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
            // Revoke users certificates
            try {
            	boolean foundCertificateOnHold = false;
            	// Find all user certs
            	Iterator i = getCertificateStoreSession().findCertificatesByUsername(administrator, username).iterator();
            	while (i.hasNext()) {
            		X509Certificate cert = (X509Certificate) i.next();
            		if (getCertificateStoreSession().isRevoked(administrator, cert.getIssuerDN().toString(),
            				cert.getSerialNumber()).getReason() == RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD) {
            			foundCertificateOnHold = true;
            			try {
                			getAdminSession().unRevokeCert(administrator, cert.getSerialNumber(), cert.getIssuerDN().toString(), username);
                        } catch (AlreadyRevokedException e) {
                        	getOutputStream().println("Error : The user was already reactivated while the request executed.");
                        } catch (ApprovalException e) {
                        	getOutputStream().println("Error : Reactivation already requested.");
                        } catch (WaitingForApprovalException e) {
                        	getOutputStream().println("Reactivation request has been sent for approval.");
            			}
            		}
            	}
            	if (!foundCertificateOnHold) {
                	getOutputStream().println("No certificates with status 'On hold' were found for this user.");
            	} else {
	                data = getAdminSession().findUser(administrator, username);
	                getOutputStream().println("New status=" + data.getStatus());
            	}
            } catch (AuthorizationDeniedException e) {
            	getOutputStream().println("Error : Not authorized to reactivate user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
