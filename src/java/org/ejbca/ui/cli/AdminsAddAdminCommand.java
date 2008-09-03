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
import java.util.Map;

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;

/**
 * Adds an admin
 *
 */
public class AdminsAddAdminCommand extends BaseAdminsAdminCommand {

	protected final static String COMMAND = "addadmin";

	public AdminsAddAdminCommand(String[] args) {
		super(args);
	}

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		try {
			if (args.length < 6) {
				getOutputStream().println("Usage: admins " + COMMAND + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
				getOutputStream().print("\nAvailable Admin groups:");
				Collection<AdminGroup> adminGroups = getAuthorizationSession().getAuthorizedAdminGroupNames(administrator);
				Collections.sort((List<AdminGroup>) adminGroups);
				for (AdminGroup adminGroup : adminGroups) {
					getOutputStream().print(" \"" + adminGroup.getAdminGroupName() + "\"");
				}
				Map caIdToNameMap = getCAAdminSession().getCAIdToNameMap(administrator);
				Collection<Integer> caids = getCAAdminSession().getAvailableCAs(administrator);
				getOutputStream().print("\n\nAvailable CAs:");
				for (Integer caid : caids) {
					getOutputStream().print(" \"" + caIdToNameMap.get(caid) + "\"");
				}
				getOutputStream().print("\n\nmatch with is one of:");
				for (String currentMatchWith : AdminEntity.MATCHWITHTEXTS) {
					getOutputStream().print("" + currentMatchWith + " ");
				}
				getOutputStream().print("\n\nmatch type is one of:");
				for (String currentMatchType : AdminEntity.MATCHTYPETEXTS) {
					getOutputStream().print(" " + currentMatchType + "");
				}
				getOutputStream().println("\n");
				return;
			}
			String groupName = args[1];
            if (getAuthorizationSession().getAdminGroup(administrator, groupName) == null) {
                getOutputStream().println("No such group \"" + groupName + "\" .");
                return;
            }
			String caName = args[2];
			CAInfo caInfo = getCAAdminSession().getCAInfo(administrator, caName);
            if (caInfo == null) {
                getOutputStream().println("No such CA \"" + caName + "\" .");
                return;
            }
			int caid = caInfo.getCAId();
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
			AdminEntity adminEntity = new AdminEntity(matchWith, matchType, matchValue, caid);
			Collection<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
			adminEntities.add(adminEntity);
			getAuthorizationSession().addAdminEntities(administrator, groupName, adminEntities);
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
