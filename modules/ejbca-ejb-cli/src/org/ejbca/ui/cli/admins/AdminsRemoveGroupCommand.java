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
 
package org.ejbca.ui.cli.admins;

import org.cesecore.roles.RoleData;
import org.ejbca.ui.cli.CliUserAuthenticationFailedException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Remove admin role
 */
public class AdminsRemoveGroupCommand extends BaseAdminsCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "removerole"; }
	public String getDescription() { return "Remove admin role"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUserAuthenticationFailedException e) {
            return;
        }
        
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of role>");
                return;
            }
            String roleName = args[1];
            RoleData role = ejb.getRoleAccessSession().findRole(roleName);
            if (role == null) {
            	getLogger().error("No such role \"" + roleName + "\" .");
                return;
            }
            ejb.getRoleManagementSession().remove(getAdmin(cliUserName, cliPassword), role);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
		}
    }
}
