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

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;

/**
 * Removes an admin
 *
 */
public class AdminsRemoveAdminCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "removeadmin";

	public AdminsRemoveAdminCommand(String[] args) {
		super(args);
	}

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			if (args.length < 6) {
				getOutputStream().println("Usage: admins " + COMMAND + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
				return;
			}
			String groupName = args[1];
			AdminGroup adminGroup = getAuthorizationSession().getAdminGroup(administrator, groupName);
            if (adminGroup == null) {
                getOutputStream().println("No such group \"" + groupName + "\" .");
                return;
            }
			String caName = args[2];
			CAInfo caInfo = getCAAdminSession().getCAInfo(administrator, caName);
            if (caInfo == null) {
                getOutputStream().println("No such CA \"" + caName + "\" .");
                return;
            }
			int matchWith = Arrays.asList(AdminEntity.MATCHWITHTEXTS).indexOf(args[3]);
            if (matchWith == -1) {
                getOutputStream().println("No such thing to match with as \"" + args[3] + "\" .");
                return;
            }
			int matchType = Arrays.asList(AdminEntity.MATCHTYPETEXTS).indexOf(args[4]) + 1000;
            if (matchType == (-1 + 1000)) {
                getOutputStream().println("No such type to match with as \"" + args[4] + "\" .");
                return;
            }
			String matchValue = args[5];
			int caid = getCAAdminSession().getCAInfo(administrator, caName).getCAId();
			AdminEntity adminEntity = new AdminEntity(matchWith, matchType, matchValue, caid);
			
            Collection<AdminEntity> list = adminGroup.getAdminEntities();
            for (AdminEntity currentAdminEntity : list) {
            	if (currentAdminEntity.getMatchValue().equals(adminEntity.getMatchValue()) && currentAdminEntity.getMatchWith() == adminEntity.getMatchWith() &&
            			currentAdminEntity.getMatchType() == adminEntity.getMatchType() && currentAdminEntity.getCaId() == adminEntity.getCaId()) {
        			Collection<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
        			adminEntities.add(adminEntity);
        			getAuthorizationSession().removeAdminEntities(administrator, groupName, adminEntities);
            		return;
            	}
            }
            getOutputStream().println("Could not find any matching admin in group \"" + groupName + "\" .");
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
