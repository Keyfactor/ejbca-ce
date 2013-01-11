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

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Adds an admin
 * 
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
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        try {
            if (args.length < 6) {         
                getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand() + " <name of role> <name of issuing CA> <match with> <match type> <match value>");
                Collection<RoleData> roles = ejb.getRemoteSession(RoleManagementSessionRemote.class).getAllRolesAuthorizedToEdit(
                        getAdmin(cliUserName, cliPassword));
                Collections.sort((List<RoleData>) roles);
                String availableRoles = "";
                for (RoleData role : roles) {
                    availableRoles += (availableRoles.length() == 0 ? "" : ", ") + "\"" + role.getRoleName() + "\"";
                }
                getLogger().info("Available Roles: " + availableRoles);
                Collection<String> canames = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCANames(getAdmin(cliUserName, cliPassword));
                String availableCas = "";
                for (String caname : canames) {
                    availableCas += (availableCas.length() == 0 ? "" : ", ") + "\"" + caname + "\"";
                }
                getLogger().info("Available CAs: " + availableCas);
                String availableMatchers = "";
                for (AccessMatchValue currentMatchWith : X500PrincipalAccessMatchValue.values()) {
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
            if (ejb.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName) == null) {
                getLogger().error("No such group \"" + roleName + "\".");
                return;
            }
            String caName = args[2];
            CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), caName);
            if (caInfo == null) {
                getLogger().error("No such CA \"" + caName + "\".");
                return;
            }
            int caid = caInfo.getCAId();
            AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.lookupMatchValueFromTokenTypeAndName(X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getTokenType(), args[3]);
            if (matchWith == null) {
                getLogger().error("No such thing to match with as \"" + args[3] + "\".");
                return;
            }
            AccessMatchType matchType = AccessMatchType.matchFromName(args[4]);
            if (matchType == null) {
                getLogger().error("No such type to match with as \"" + args[4] + "\".");
                return;
            }
            String matchValue = args[5];
            AccessUserAspectData accessUser = new AccessUserAspectData(roleName, caid, matchWith, matchType, matchValue);
            Collection<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
            accessUsers.add(accessUser);
            ejb.getRemoteSession(RoleManagementSessionRemote.class).addSubjectsToRole(getAdmin(cliUserName, cliPassword), ejb.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName),
                    accessUsers);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
