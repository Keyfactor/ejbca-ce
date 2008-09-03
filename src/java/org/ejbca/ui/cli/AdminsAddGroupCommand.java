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
 * Adds a new admin group
 *
 */
public class AdminsAddGroupCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "addgroup";

	public AdminsAddGroupCommand(String[] args) {
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
            getAuthorizationSession().addAdminGroup(administrator, groupName);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
		}
    }
}
