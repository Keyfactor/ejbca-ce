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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Find details of a user in the database.
 *
 * @version $Id$
 */
public class RaFindUserCommand extends BaseRaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "finduser"; }
	public String getDescription() { return "Find and show details of a user"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <username>");
                return;
            }
            String username = args[1];
            try {
                EndEntityInformation data = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAdmin(cliUserName, cliPassword), username);
                if (data != null) {
                	getLogger().info("Found user:");
                	getLogger().info("Username: " + data.getUsername());
                    getLogger().info("Password: " + (data.getPassword() != null ? data.getPassword() : "*****"));
                    getLogger().info("DN: \"" + data.getDN() + "\"");
                    getLogger().info("Alt Name: \"" + data.getSubjectAltName() + "\"");
                    ExtendedInformation ei = data.getExtendedinformation();
                    getLogger().info("Directory Attributes: \"" + (ei != null ? ei.getSubjectDirectoryAttributes() : "") + "\"");
                    getLogger().info("E-Mail: " + data.getEmail());
                    getLogger().info("Status: " + data.getStatus());
                    getLogger().info("Type: " + data.getType().getHexValue());
                    getLogger().info("Token Type: " + data.getTokenType());
                    getLogger().info("End Entity Profile ID: " + data.getEndEntityProfileId());
                    getLogger().info("Certificate Profile ID: " + data.getCertificateProfileId());
                    getLogger().info("Hard Token Issuer ID: " + data.getHardTokenIssuerId());
                    getLogger().info("Created: " + data.getTimeCreated());
                    getLogger().info("Modified: " + data.getTimeModified());
                } else {
                    getLogger().error("User '" + username + "' does not exist.");
                }
            } catch (AuthorizationDeniedException e) {
                getLogger().error("Error : Not authorized to view user.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
