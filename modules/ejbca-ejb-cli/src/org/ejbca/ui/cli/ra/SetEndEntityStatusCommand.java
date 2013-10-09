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
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes status for an end entity in the database, status is defined in
 * org.cesecore.certificates.endentity.EndEntityConstants
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class SetEndEntityStatusCommand extends BaseRaCommand {
    
    private static final String COMMAND = "setendentitystatus";
    private static final String OLD_COMMAND = "setuserstatus";
    
    @Override
	public String getSubCommand() { return COMMAND; }

    @Override
	public String getDescription() { return "Change status for an end entity"; }

    @Override
    public String[] getSubCommandAliases() {
        return new String[]{OLD_COMMAND};
    }
    
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 3) {
    			getLogger().info("Description: " + getDescription());
            	getLogger().info("Usage: " + getCommand() + " <username> <status>");
            	getLogger().info(" Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                return;
            }
            String username = args[1];
            int status = Integer.parseInt(args[2]);
            try {
                ejb.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAuthenticationToken(cliUserName, cliPassword), username, status);
                getLogger().info("New status for end entity " + username + " is " + status);
            } catch (AuthorizationDeniedException e) {
            	getLogger().error("Not authorized to change end entity.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
