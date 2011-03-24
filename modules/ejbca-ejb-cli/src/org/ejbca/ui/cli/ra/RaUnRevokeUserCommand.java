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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Reactivates a user if the revocation reason is 'on hold'.
 *
 * @version $Id$
 */
public class RaUnRevokeUserCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "unrevokeuser"; }
	public String getDescription() { return "Reactivates a user if the revocation reason is 'on hold'"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
            	getLogger().info("Usage: " + getCommand() + " <username>");
            	getLogger().info(" A users certificate can unly be unrevoked if the revocation reason is certificate_hold.");
                return;
            }
            String username = args[1];
            UserDataVO data = ejb.getUserAdminSession().findUser(getAdmin(), username);
            getLogger().info("Found user:");
            getLogger().info("username=" + data.getUsername());
            getLogger().info("dn=\"" + data.getDN() + "\"");
            getLogger().info("Old status=" + data.getStatus());
            // Revoke users certificates
            try {
            	boolean foundCertificateOnHold = false;
            	// Find all user certs
            	Iterator<Certificate> i = ejb.getCertStoreSession().findCertificatesByUsername(getAdmin(), username).iterator();
            	while (i.hasNext()) {
            		X509Certificate cert = (X509Certificate) i.next();
            		if (ejb.getCertStoreSession().getStatus(cert.getIssuerDN().toString(),
            				cert.getSerialNumber()).revocationReason == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
            			foundCertificateOnHold = true;
            			try {
            				ejb.getUserAdminSession().revokeCert(getAdmin(), cert.getSerialNumber(), cert.getIssuerDN().toString(), RevokedCertInfo.NOT_REVOKED);
                        } catch (AlreadyRevokedException e) {
                        	getLogger().error("The user was already reactivated while the request executed.");
                        } catch (ApprovalException e) {
                        	getLogger().error("Reactivation already requested.");
                        } catch (WaitingForApprovalException e) {
                        	getLogger().info("Reactivation request has been sent for approval.");
            			}
            		}
            	}
            	if (!foundCertificateOnHold) {
            		getLogger().error("No certificates with status 'On hold' were found for this user.");
            	} else {
	                data = ejb.getUserAdminSession().findUser(getAdmin(), username);
	                getLogger().info("New status=" + data.getStatus());
            	}
            } catch (AuthorizationDeniedException e) {
            	getLogger().error("Not authorized to reactivate user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
