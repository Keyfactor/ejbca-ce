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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.RoleData;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Adds an admin
 * @version $Id$
 */
public class AdminsAddAdminCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "addadmin";
    }

    public String getDescription() {
        return "Adds an administrator";
    }

    /** @see org.ejbca.ui.cli.CliCommandPlugin */
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 6) {
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
                Collection<RoleData> adminGroups = ejb.getComplexAccessControlSession().getAllRolesAuthorizedToEdit(getAdmin()); 
                Collections.sort((List<RoleData>) adminGroups);
                String availableGroups = "";
                for (RoleData adminGroup : adminGroups) {
                    availableGroups += (availableGroups.length() == 0 ? "" : ", ") + "\"" + adminGroup.getRoleName() + "\"";
                }
                getLogger().info("Available Admin groups: " + availableGroups);
                Map<Integer, String> caIdToNameMap = ejb.getCAAdminSession().getCAIdToNameMap(getAdmin());
                Collection<Integer> caids = ejb.getCaSession().getAvailableCAs(getAdmin());
                String availableCas = "";
                for (Integer caid : caids) {
                    availableCas += (availableCas.length() == 0 ? "" : ", ") + "\"" + caIdToNameMap.get(caid) + "\"";
                }
                getLogger().info("Available CAs: " + availableCas);
                String availableMatchers = "";
                for (AccessMatchValue currentMatchWith : AccessMatchValue.values()) {
                    availableMatchers += (availableMatchers.length() == 0 ? "" : ", ") + currentMatchWith;
                }
                getLogger().info("Match with is one of: " + availableMatchers);
                String availableMatchTypes = "";
                for (AccessMatchType currentMatchType : AccessMatchType.values()) {
                    availableMatchTypes += (availableMatchTypes.length() == 0 ? "" : ", ") + currentMatchType;
                }
                getLogger().info("Match type is one of: " + availableMatchTypes);
                return;
            }
            String roleName = args[1];
            if (ejb.getRoleAccessSession().findRole(roleName) == null) {
                getLogger().error("No such group \"" + roleName + "\" .");
                return;
            }
            String caName = args[2];
            CAInfo caInfo = ejb.getCaSession().getCAInfo(getAdmin(), caName);
            if (caInfo == null) {
                getLogger().error("No such CA \"" + caName + "\" .");
                return;
            }
            int caid = caInfo.getCAId();
            AccessMatchValue matchWith = AccessMatchValue.matchFromName(args[3]); 
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
            AccessUserAspectData subject = new AccessUserAspectData(roleName, caid, matchWith, matchType, matchValue);
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(subject);
            ejb.getRoleManagementSession().addSubjectsToRole(getAdmin(), ejb.getRoleAccessSession().findRole(roleName), subjects);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
