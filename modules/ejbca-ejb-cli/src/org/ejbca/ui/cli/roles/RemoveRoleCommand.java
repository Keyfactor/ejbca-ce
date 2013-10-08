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
 
package org.ejbca.ui.cli.roles;

import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Remove admin role
 */
public class RemoveRoleCommand extends BaseRolesCommand {
    
    @Override
    public String getSubCommand() { return "removerole"; }
	@Override
	public String getDescription() { return "Remove admin role"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of role>");
                return;
            }
            String roleName = args[1];
            RoleData role = ejb.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName);
            if (role == null) {
            	getLogger().error("No such role \"" + roleName + "\".");
                return;
            }
            ejb.getRemoteSession(RoleManagementSessionRemote.class).remove(getAdmin(cliUserName, cliPassword), role);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
		}
    }
}
