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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Removes an admin
 * @version $Id$
 */
public class AdminsRemoveAdminCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "removeadmin";
    }

    public String getDescription() {
        return "Removes an admin";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 6) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
                return;
            }
            String groupName = args[1];
            AdminGroup adminGroup = ejb.getRoleAccessSession().getAdminGroup(getAdmin(), groupName);
            if (adminGroup == null) {
                getLogger().error("No such group \"" + groupName + "\" .");
                return;
            }
            String caName = args[2];
            CAInfo caInfo = ejb.getCaSession().getCAInfo(getAdmin(), caName);
            if (caInfo == null) {
                getLogger().error("No such CA \"" + caName + "\" .");
                return;
            }
            int matchWith = Arrays.asList(AdminEntity.MATCHWITHTEXTS).indexOf(args[3]);
            if (matchWith == -1) {
                getLogger().error("No such thing to match with as \"" + args[3] + "\" .");
                return;
            }
            int matchType = Arrays.asList(AdminEntity.MATCHTYPETEXTS).indexOf(args[4]) + 1000;
            if (matchType == (-1 + 1000)) {
                getLogger().error("No such type to match with as \"" + args[4] + "\" .");
                return;
            }
            String matchValue = args[5];
            int caid = ejb.getCaSession().getCAInfo(getAdmin(), caName).getCAId();
            AdminEntity adminEntity = new AdminEntity(matchWith, matchType, matchValue, caid);

            Collection<AdminEntity> list = adminGroup.getAdminEntities();
            for (AdminEntity currentAdminEntity : list) {
                if (currentAdminEntity.getMatchValue().equals(adminEntity.getMatchValue()) && currentAdminEntity.getMatchWith() == adminEntity.getMatchWith()
                        && currentAdminEntity.getMatchType() == adminEntity.getMatchType() && currentAdminEntity.getCaId() == adminEntity.getCaId()) {
                    Collection<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
                    adminEntities.add(adminEntity);
                    ejb.getAdminEntitySession().removeAdminEntities(getAdmin(), groupName, adminEntities);
                    return;
                }
            }
            getLogger().info("Could not find any matching admin in group \"" + groupName + "\" .");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
