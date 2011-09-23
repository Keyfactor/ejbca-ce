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
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists admin groups
 * @version $Id$
 */
public class AdminsListGroupsCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "listroles";
    }

    public String getDescription() {
        return "Lists admin roles";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        args = parseUsernameAndPasswordFromArgs(args);
        
        try {
            Collection<RoleData> adminGroups = ejb.getComplexAccessControlSession().getAllRolesAuthorizedToEdit(getAdmin(cliUserName, cliPassword));            
            Collections.sort((List<RoleData>) adminGroups);
            for (RoleData adminGroup : adminGroups) {                
                int numberOfAdmins = adminGroup.getAccessUsers().size();
                getLogger().info(adminGroup.getRoleName() + " (" + numberOfAdmins + " admin" + (numberOfAdmins == 1 ? "" : "s") + ")");
            }
        } catch (Exception e) {
            getLogger().error("", e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
