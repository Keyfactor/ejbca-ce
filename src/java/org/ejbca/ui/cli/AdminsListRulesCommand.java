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
 
package org.ejbca.ui.cli;

import java.util.Collections;
import java.util.List;

import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;

/**
 * Lists access rules for a group
 *
 */
public class AdminsListRulesCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "listrules";

	public AdminsListRulesCommand(String[] args) {
        super(args);
    }

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length < 2) {
                getOutputStream().println("Usage: admins " + COMMAND + " <name of group>");
                return;
            }
            String groupName = args[1];
            AdminGroup adminGroup = getAuthorizationSession().getAdminGroup(administrator, groupName);
            if (adminGroup == null) {
                getOutputStream().println("No such group \"" + groupName + "\" .");
                return;
            }
            List<AccessRule> list = (List<AccessRule>) adminGroup.getAccessRules();
            Collections.sort(list);
            for (AccessRule accessRule : list) {
            	getOutputStream().println(getParsedAccessRule(accessRule.getAccessRule()) + " " + AccessRule.RULE_TEXTS[accessRule.getRule()] + " " + (accessRule.isRecursive() ? "RECURSIVE" : ""));
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
		}
    }
}
