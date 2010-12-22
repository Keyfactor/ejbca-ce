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

import org.ejbca.core.model.authorization.AdminGroup;
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
        return "listgroups";
    }

    public String getDescription() {
        return "Lists admin groups";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            Collection<AdminGroup> adminGroups = ejb.getAdminGroupSession().getAuthorizedAdminGroupNames(getAdmin(), ejb.getCaSession().getAvailableCAs(getAdmin()));
            Collections.sort((List<AdminGroup>) adminGroups);
            for (AdminGroup adminGroupRep : adminGroups) {
                AdminGroup adminGroup = ejb.getAdminGroupSession().getAdminGroup(getAdmin(), adminGroupRep.getAdminGroupName());
                int numberOfAdmins = adminGroup.getNumberAdminEntities();
                getLogger().info(adminGroup.getAdminGroupName() + " (" + numberOfAdmins + " admin" + (numberOfAdmins == 1 ? "" : "s") + ")");
            }
        } catch (Exception e) {
            getLogger().error("", e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
