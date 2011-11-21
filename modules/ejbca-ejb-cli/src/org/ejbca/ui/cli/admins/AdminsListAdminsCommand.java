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

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.roles.RoleData;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists admins in a role
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
        return "Lists admins in a role";
    }

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
            RoleData adminGroup = ejb.getRoleAccessSession().findRole(roleName);
            if (adminGroup == null) {
                getLogger().error("No such role \"" + roleName + "\" .");
                return;
            }
            for (AccessUserAspectData userAspect : adminGroup.getAccessUsers().values()) {
                String caName;
                try {  
                    CAInfo info = ejb.getCaSession().getCAInfo(getAdmin(cliUserName, cliPassword), userAspect.getCaId());
                    caName = info.getName();
                } catch(CADoesntExistsException e) {
                    caName = "Unknown CA with id " + userAspect.getCaId();
                }       
                AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(userAspect.getTokenType(), userAspect.getMatchWith());
                AccessMatchType matchType = userAspect.getMatchTypeAsType();     
                String matchValue = userAspect.getMatchValue();
                getLogger().info("\"" + caName + "\" " + matchWith + " " + matchType + " \"" + matchValue + "\"");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
