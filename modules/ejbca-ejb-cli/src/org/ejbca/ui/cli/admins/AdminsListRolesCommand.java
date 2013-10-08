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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.cesecore.roles.RoleData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists admin roles
 * @version $Id$
 */
public class AdminsListRolesCommand extends BaseAdminsCommand {


    @Override
    public String getSubCommand() {
        return "listroles";
    }
    @Override
    public String getDescription() {
        return "Lists admin roles";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            Collection<RoleData> roles = ejb.getRemoteSession(RoleManagementSessionRemote.class).getAllRolesAuthorizedToEdit(getAdmin(cliUserName, cliPassword));            
            Collections.sort((List<RoleData>) roles);
            for (RoleData role : roles) {                
                int numberOfAdmins = role.getAccessUsers().size();
                getLogger().info(role.getRoleName() + " (" + numberOfAdmins + " admin" + (numberOfAdmins == 1 ? "" : "s") + ")");
            }
        } catch (Exception e) {
            getLogger().error("", e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
