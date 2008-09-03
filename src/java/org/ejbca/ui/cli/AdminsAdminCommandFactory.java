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

/**
 * Factory for Admin Admin Commands.
 *
 */
public class AdminsAdminCommandFactory {
	/**
	 * Cannot create an instance of this class, only use static methods.
	 */
	private AdminsAdminCommandFactory() { }
	
	/**
	 * Returns an Admin Command object based on contents in args[0].
	 *
	 * @param args array of arguments typically passed from main().
	 *
	 * @return Command object or null if args[0] does not specify a valid command.
	 */
	public static IAdminCommand getCommand(String[] args) {
		if (args.length < 1) {
			return null;
		}
		if (args[0].equals(AdminsListGroupsCommand.COMMAND)) {
			return new AdminsListGroupsCommand(args);
		} else if (args[0].equals(AdminsAddGroupCommand.COMMAND)) {
			return new AdminsAddGroupCommand(args);
		} else if (args[0].equals(AdminsRemoveGroupCommand.COMMAND)) {
			return new AdminsRemoveGroupCommand(args);
		} else if (args[0].equals(AdminsListAdminsCommand.COMMAND)) {
			return new AdminsListAdminsCommand(args);
		} else if (args[0].equals(AdminsAddAdminCommand.COMMAND)) {
			return new AdminsAddAdminCommand(args);
		} else if (args[0].equals(AdminsRemoveAdminCommand.COMMAND)) {
			return new AdminsRemoveAdminCommand(args);
		} else if (args[0].equals(AdminsListRulesCommand.COMMAND)) {
			return new AdminsListRulesCommand(args);
		} else if (args[0].equals(AdminsChangeRuleCommand.COMMAND)) {
			return new AdminsChangeRuleCommand(args);
		}
		return null;
	}
}
