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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.ejbca.core.model.authorization.AdminGroup;

/**
 * Lists admin groups
 *
 */
public class AdminsListGroupsCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "listgroups";

	public AdminsListGroupsCommand(String[] args) {
        super(args);
    }

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
        	Collection<AdminGroup> adminGroups = getAuthorizationSession().getAuthorizedAdminGroupNames(administrator);
        	Collections.sort((List<AdminGroup>) adminGroups);
        	for (AdminGroup adminGroupRep : adminGroups) {
        		AdminGroup adminGroup = getAuthorizationSession().getAdminGroup(administrator, adminGroupRep.getAdminGroupName());
        		int numberOfAdmins = adminGroup.getNumberAdminEntities();
        		getOutputStream().println(adminGroup.getAdminGroupName() + " (" +  numberOfAdmins + " admin" + (numberOfAdmins == 1 ? "" : "s") + ")");
        	}
        } catch (Exception e) {
        	error("",e);
            throw new ErrorAdminCommandException(e);
        }
    }
}
