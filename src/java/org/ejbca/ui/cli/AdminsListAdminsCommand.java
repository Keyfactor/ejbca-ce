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

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;

/**
 * Lists admins in a group
 *
 */
public class AdminsListAdminsCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "listadmins";

	public AdminsListAdminsCommand(String[] args) {
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
            Collection<AdminEntity> list = adminGroup.getAdminEntities();
            for (AdminEntity adminEntity : list) {
            	String caName = (String) getCAAdminSession().getCAIdToNameMap(administrator).get(adminEntity.getCaId());
            	if (caName == null) {
            		caName = "Unknown CA with id " + adminEntity.getCaId();
            	}
            	String matchWith = adminEntity.MATCHWITHTEXTS[adminEntity.getMatchWith()];
            	String matchType = "SPECIAL";
        		if (adminEntity.getMatchType() < AdminEntity.SPECIALADMIN_PUBLICWEBUSER) {
                	matchType = AdminEntity.MATCHTYPETEXTS[adminEntity.getMatchType()-1000];
        		}
        		String matchValue = adminEntity.getMatchValue();
            	getOutputStream().println("\"" + caName + "\" " +  matchWith + " " + matchType + " \"" + matchValue + "\"");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
		}
    }
}
