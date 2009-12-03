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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Adds an admin
 */
public class AdminsAddAdminCommand extends BaseAdminsCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "addadmin"; }
	public String getDescription() { return "Adds an administartor"; }

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute(String[] args) throws ErrorAdminCommandException {
		try {
			if (args.length < 6) {
    			getLogger().info("Description: " + getDescription());
				getLogger().info("Usage: " + getCommand() + " <name of group> <name of issuing CA> <match with> <match type> <match value>");
				Collection<AdminGroup> adminGroups = getAuthorizationSession().getAuthorizedAdminGroupNames(getAdmin(), getCAAdminSession().getAvailableCAs(getAdmin()));
				Collections.sort((List<AdminGroup>) adminGroups);
				String availableGroups = "";
				for (AdminGroup adminGroup : adminGroups) {
					availableGroups += (availableGroups.length()==0?"":", ") + "\"" + adminGroup.getAdminGroupName() + "\"";
				}
				getLogger().info("Available Admin groups: " + availableGroups);
				Map caIdToNameMap = getCAAdminSession().getCAIdToNameMap(getAdmin());
				Collection<Integer> caids = getCAAdminSession().getAvailableCAs(getAdmin());
				String availableCas = "";
				for (Integer caid : caids) {
					availableCas += (availableCas.length()==0?"":", ") + "\"" + caIdToNameMap.get(caid) + "\"";
				}
				getLogger().info("Available CAs: " + availableCas);
				String availableMatchers = "";
				for (String currentMatchWith : AdminEntity.MATCHWITHTEXTS) {
					availableMatchers += (availableMatchers.length()==0?"":", ") + currentMatchWith;
				}
				getLogger().info("Match with is one of: " + availableMatchers);
				String availableMatchTypes = "";
				for (String currentMatchType : AdminEntity.MATCHTYPETEXTS) {
					availableMatchTypes += (availableMatchTypes.length()==0?"":", ") + currentMatchType; 
				}
				getLogger().info("Match type is one of: " + availableMatchTypes);
				return;
			}
			String groupName = args[1];
            if (getAuthorizationSession().getAdminGroup(getAdmin(), groupName) == null) {
            	getLogger().error("No such group \"" + groupName + "\" .");
                return;
            }
			String caName = args[2];
			CAInfo caInfo = getCAAdminSession().getCAInfo(getAdmin(), caName);
            if (caInfo == null) {
            	getLogger().error("No such CA \"" + caName + "\" .");
                return;
            }
			int caid = caInfo.getCAId();
			int matchWith = Arrays.asList(AdminEntity.MATCHWITHTEXTS).indexOf(args[3]);
            if (matchWith == -1) {
            	getLogger().error("No such thing to match with as \"" + args[3] + "\" .");
                return;
            }
			int matchType = Arrays.asList(AdminEntity.MATCHTYPETEXTS).indexOf(args[4]) + 1000;
            if (matchType == (-1 + 1000)) {
            	getLogger().error("No such type to match with as \"" + args[4] + "\" .");
                return;
            }
			String matchValue = args[5];
			AdminEntity adminEntity = new AdminEntity(matchWith, matchType, matchValue, caid);
			Collection<AdminEntity> adminEntities = new ArrayList<AdminEntity>();
			adminEntities.add(adminEntity);
			getAuthorizationSession().addAdminEntities(getAdmin(), groupName, adminEntities);
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}
}
