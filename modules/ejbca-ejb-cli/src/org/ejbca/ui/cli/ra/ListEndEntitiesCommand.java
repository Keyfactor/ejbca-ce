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

import java.util.Collection;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * List end entities with specified status in the database.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class ListEndEntitiesCommand extends BaseRaCommand {
    
    private static final String COMMAND = "listendentities";
    private static final String OLD_COMMAND = "listusers";
    
    @Override
	public String getSubCommand() { return COMMAND; }
    
    @Override
    public String getDescription() { return "List end entities with a specified status"; }
    
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
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <status>");
                getLogger().info(" Status: ANY=00; NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; REVOKED=50; HISTORICAL=60; KEYRECOVERY=70");
                return;
            }
            int status = Integer.parseInt(args[1]);
            Collection<EndEntityInformation> coll = null;
            if (status==0) {
                coll = ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 10);
                coll.addAll(ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 11));
                coll.addAll(ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 20));
                coll.addAll(ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 30));
                coll.addAll(ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 40));
                coll.addAll(ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), 50));
            } else {
                coll = ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), status);
            }
            if(coll.size() == 0) {
                getLogger().info("No end entities with status " + status + " found.");
            } else {
                for (EndEntityInformation endEntityInformation : coll) {
                    getLogger().info(
                            "End Entity: " + endEntityInformation.getUsername() + ", \"" + endEntityInformation.getDN() + "\", \""
                                    + endEntityInformation.getSubjectAltName() + "\", " + endEntityInformation.getEmail() + ", "
                                    + endEntityInformation.getStatus() + ", " + endEntityInformation.getType().getHexValue() + ", "
                                    + endEntityInformation.getTokenType() + ", " + endEntityInformation.getHardTokenIssuerId());
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
