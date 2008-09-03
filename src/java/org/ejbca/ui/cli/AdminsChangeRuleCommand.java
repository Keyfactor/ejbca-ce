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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;

/**
 * Changes an access rule
 *
 */
public class AdminsChangeRuleCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "changerule";

	public AdminsChangeRuleCommand(String[] args) {
		super(args);
	}

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			if (args.length < 5) {
				getOutputStream().println("Usage: admins " + COMMAND + " <name of group> <access rule> <rule> <recursive>");
				getOutputStream().print("\nAvailable Admin groups:");
				Collection<AdminGroup> adminGroups = getAuthorizationSession().getAuthorizedAdminGroupNames(administrator);
				Collections.sort((List<AdminGroup>) adminGroups);
				for (AdminGroup adminGroup : adminGroups) {
					getOutputStream().print(" \"" + adminGroup.getAdminGroupName() + "\"");
				}
				getOutputStream().println("\n\naccess rule is one of:");
				for (String current : (Collection<String>) getAuthorizationSession().getAuthorizedAvailableAccessRules(administrator)) {
					getOutputStream().println(" " + getParsedAccessRule(current));
				}
				getOutputStream().print("\nrule is one of:");
				for (String current : AccessRule.RULE_TEXTS) {
					getOutputStream().print(" " + current);
				}
				getOutputStream().print("\n\nrecursive is one of: TRUE, FALSE");
				getOutputStream().println("\n");
				return;
			}
			String groupName = args[1];
            if (getAuthorizationSession().getAdminGroup(administrator, groupName) == null) {
                getOutputStream().println("No such group \"" + groupName + "\" .");
                return;
            }
			String accessRule = getOriginalAccessRule(args[2]);
			if (!((Collection<String>) getAuthorizationSession().getAuthorizedAvailableAccessRules(administrator)).contains(accessRule)) {
				getOutputStream().println("Accessrule \"" + accessRule + "\" is not available.");
				return;
			}
			int rule = Arrays.asList(AccessRule.RULE_TEXTS).indexOf(args[3]);
			if (rule == -1) {
				getOutputStream().println("No such rule \"" + args[3] + "\".");
				return;
			}
			boolean recursive = "TRUE".equalsIgnoreCase(args[4]);
			Collection<String> accessRuleStrings = new ArrayList<String>();
			accessRuleStrings.add(accessRule);
			if (rule == AccessRule.RULE_NOTUSED) {
				getAuthorizationSession().removeAccessRules(administrator, groupName, accessRuleStrings);
			} else {
				getAuthorizationSession().removeAccessRules(administrator, groupName, accessRuleStrings);
				AccessRule accessRuleObject = new AccessRule(accessRule, rule, recursive);
				Collection<AccessRule> accessRules = new ArrayList<AccessRule>();
				accessRules.add(accessRuleObject);
				getAuthorizationSession().addAccessRules(administrator, groupName, accessRules);
			}
		} catch (Exception e) {
			error("",e);
			throw new ErrorAdminCommandException(e);
		}
	}
}
