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
import java.util.Collection;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.RoleData;
import org.ejbca.ui.cli.CliUsernameException;
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
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            if (args.length < 6) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
                return;
            }
            String roleName = args[1];     
            RoleData role = ejb.getRoleAccessSession().findRole(roleName);
            if (role == null) {
                getLogger().error("No such role \"" + roleName + "\" .");
                return;
            }
            String caName = args[2];
            CAInfo caInfo = ejb.getCaSession().getCAInfo(getAdmin(cliUserName, cliPassword), caName);
            if (caInfo == null) {
                getLogger().error("No such CA \"" + caName + "\" .");
                return;
            }
            X500PrincipalAccessMatchValue matchWith = X500PrincipalAccessMatchValue.matchFromName(args[3]);
            if (matchWith == null) {
                getLogger().error("No such thing to match with as \"" + args[3] + "\" .");
                return;
            }
            AccessMatchType matchType = AccessMatchType.matchFromName(args[4]);  
            if (matchType == null) {
                getLogger().error("No such type to match with as \"" + args[4] + "\" .");
                return;
            }
            String matchValue = args[5];
            int caId = ejb.getCaSession().getCAInfo(getAdmin(cliUserName, cliPassword), caName).getCAId();
            AccessUserAspectData accessUserAspectData = new AccessUserAspectData(roleName, caId, matchWith, matchType, matchValue);
            
            for (AccessUserAspectData currentAdminEntity : role.getAccessUsers().values()) {
                if (currentAdminEntity.getMatchValue().equals(accessUserAspectData.getMatchValue()) && currentAdminEntity.getMatchWith() == accessUserAspectData.getMatchWith()
                        && currentAdminEntity.getMatchType() == accessUserAspectData.getMatchType() && currentAdminEntity.getCaId() == accessUserAspectData.getCaId()) {
                    Collection<AccessUserAspectData> adminEntities = new ArrayList<AccessUserAspectData>();
                    adminEntities.add(accessUserAspectData);
                   
                    ejb.getRoleManagementSession().removeSubjectsFromRole(getAdmin(cliUserName, cliPassword), role, adminEntities);
                   
                    return;
                }
            }
            getLogger().info("Could not find any matching admin in group \"" + roleName + "\" .");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
