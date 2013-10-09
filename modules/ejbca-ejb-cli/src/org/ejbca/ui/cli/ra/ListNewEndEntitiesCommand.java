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
import java.util.Iterator;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * List end entities with status NEW in the database.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class ListNewEndEntitiesCommand extends BaseRaCommand {
    
    private static final String COMMAND = "listnewendentities";
    private static final String OLD_COMMAND = "listnewusers";
    
    @Override
	public String getSubCommand() { return COMMAND; }
    
    @Override
    public String getDescription() { return "List end entities with status 'NEW'"; }
    
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
            Collection<EndEntityInformation> coll = ejb.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(cliUserName, cliPassword), EndEntityConstants.STATUS_NEW);
            Iterator<EndEntityInformation> iter = coll.iterator();
            while (iter.hasNext()) {
            	EndEntityInformation data = iter.next();
                getLogger().info("New end entity: " + data.getUsername() + ", \"" + data.getDN() +
                    "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail() + ", " +
                    data.getStatus() + ", " + data.getType().getHexValue() + ", " + data.getTokenType());
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
