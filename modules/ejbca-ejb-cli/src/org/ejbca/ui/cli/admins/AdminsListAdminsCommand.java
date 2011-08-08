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

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists admins in a group
 * @version $Id$
 */
public class AdminsListAdminsCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "listadmins";
    }

    public String getDescription() {
        return "Lists admins in a group";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of group>");
                return;
            }
            String groupName = args[1];
            AdminGroup adminGroup = ejb.getRoleAccessSession().getAdminGroup(getAdmin(), groupName);
            if (adminGroup == null) {
                getLogger().error("No such group \"" + groupName + "\" .");
                return;
            }
            Collection<AdminEntity> list = adminGroup.getAdminEntities();
            for (AdminEntity adminEntity : list) {
                String caName = (String) ejb.getCAAdminSession().getCAIdToNameMap(getAdmin()).get(adminEntity.getCaId());
                if (caName == null) {
                    caName = "Unknown CA with id " + adminEntity.getCaId();
                }
                String matchWith = AdminEntity.MATCHWITHTEXTS[adminEntity.getMatchWith()];
                String matchType = "SPECIAL";
                if (adminEntity.getMatchType() < AdminEntity.SPECIALADMIN_PUBLICWEBUSER) {
                    matchType = AdminEntity.MATCHTYPETEXTS[adminEntity.getMatchType() - 1000];
                }
                String matchValue = adminEntity.getMatchValue();
                getLogger().info("\"" + caName + "\" " + matchWith + " " + matchType + " \"" + matchValue + "\"");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
