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
import java.util.Collections;
import java.util.List;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSession;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Lists access rules for a role
 * 
 * @version $Id$
 */
public class AdminsListRulesCommand extends BaseAdminsCommand {

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "listrules";
    }

    public String getDescription() {
        return "Lists access rules for a role";
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
            String groupName = args[1];
            RoleData role = ejb.getRemoteSession(RoleAccessSession.class).findRole(groupName);
            if (role == null) {
                getLogger().error("No such role \"" + groupName + "\".");
                return;
            }
            List<AccessRuleData> list = new ArrayList<AccessRuleData>(role.getAccessRules().values());
            Collections.sort(list);
            for (AccessRuleData accessRule : list) {
                getLogger().info(
                        getParsedAccessRule(getAdmin(cliUserName, cliPassword), accessRule.getAccessRuleName()) + " " + accessRule.getInternalState().getName() + " "
                                + (accessRule.getRecursive() ? "RECURSIVE" : ""));
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
