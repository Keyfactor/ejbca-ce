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

import java.rmi.RemoteException;
import java.util.Map;

import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.ui.cli.BaseCommand;

/**
 * Base for Admins commands, contains common functions for Admins operations
 *
 */
public abstract class BaseAdminsCommand extends BaseCommand {

	protected static final String MAINCOMMAND = "admins";
	
	protected String getParsedAccessRule(String resource) throws NumberFormatException, RemoteException {
		// Check if it is a profile rule, then replace profile id with profile name.
		if (resource.startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)) {
			if (resource.lastIndexOf('/') < AvailableAccessRules.ENDENTITYPROFILEPREFIX.length()) {
				return AvailableAccessRules.ENDENTITYPROFILEPREFIX + getRaAdminSession().getEndEntityProfileName(
						getAdmin(), Integer.parseInt(resource.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())));
			} else {
				String tmpString = resource.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length());
				return AvailableAccessRules.ENDENTITYPROFILEPREFIX + getRaAdminSession().getEndEntityProfileName(
						getAdmin(), Integer.parseInt(tmpString.substring(0, tmpString.indexOf('/')))) + tmpString.substring(tmpString.indexOf('/'));
			}
		}
		// Check if it is a CA rule, then replace CA id with CA name.
		if (resource.startsWith(AvailableAccessRules.CAPREFIX)) {
			Map caIdToNameMap = getCAAdminSession().getCAIdToNameMap(getAdmin());
			if(resource.lastIndexOf('/') < AvailableAccessRules.CAPREFIX.length()) {
				return AvailableAccessRules.CAPREFIX + caIdToNameMap.get(new Integer(resource.substring(AvailableAccessRules.CAPREFIX.length())));
			} else {
				return AvailableAccessRules.CAPREFIX + caIdToNameMap.get(new Integer(resource.substring(AvailableAccessRules.CAPREFIX.length(),
						resource.lastIndexOf('/')))) + resource.substring(resource.lastIndexOf('/'));
			}
		}
		// Check if it is a User Data Source rule, then replace User Data Source id with User Data Source name.
		if (resource.startsWith(AvailableAccessRules.USERDATASOURCEPREFIX)) { 
			if (resource.lastIndexOf('/') < AvailableAccessRules.USERDATASOURCEPREFIX.length()) {
				return AvailableAccessRules.USERDATASOURCEPREFIX + getUserDataSourceSession().getUserDataSourceName(
						getAdmin(), Integer.parseInt(resource.substring(AvailableAccessRules.USERDATASOURCEPREFIX.length())));
			} else {
				return AvailableAccessRules.USERDATASOURCEPREFIX + getUserDataSourceSession().getUserDataSourceName(
						getAdmin(), Integer.parseInt(resource.substring(AvailableAccessRules.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/')))) +
						resource.substring(resource.lastIndexOf('/'));
			}
		}
		return resource;
	}

	protected String getOriginalAccessRule(String resource) throws NumberFormatException, RemoteException {
		// Check if it is a profile rule, then replace profile id with profile name.
		if (resource.startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)) {
			if (resource.lastIndexOf('/') < AvailableAccessRules.ENDENTITYPROFILEPREFIX.length()) {
				return AvailableAccessRules.ENDENTITYPROFILEPREFIX + getRaAdminSession().getEndEntityProfileId(
						getAdmin(), resource.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length()));
			} else {
				String tmpString = resource.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length());
				return AvailableAccessRules.ENDENTITYPROFILEPREFIX + getRaAdminSession().getEndEntityProfileId(
						getAdmin(), tmpString.substring(0, tmpString.indexOf('/'))) + tmpString.substring(tmpString.indexOf('/'));
			}
		}
		// Check if it is a CA rule, then replace CA id with CA name.
		if (resource.startsWith(AvailableAccessRules.CAPREFIX)) {
			if(resource.lastIndexOf('/') < AvailableAccessRules.CAPREFIX.length()) {
				return AvailableAccessRules.CAPREFIX + getCAAdminSession().getCAInfo(getAdmin(), resource.substring(AvailableAccessRules.CAPREFIX.length())).getCAId();
			} else {
				return AvailableAccessRules.CAPREFIX + getCAAdminSession().getCAInfo(getAdmin(), resource.substring(AvailableAccessRules.CAPREFIX.length(),
						resource.lastIndexOf('/'))).getCAId() + resource.substring(resource.lastIndexOf('/'));
			}
		}
		// Check if it is a User Data Source rule, then replace User Data Source id with User Data Source name.
		if (resource.startsWith(AvailableAccessRules.USERDATASOURCEPREFIX)) { 
			if (resource.lastIndexOf('/') < AvailableAccessRules.USERDATASOURCEPREFIX.length()) {
				return AvailableAccessRules.USERDATASOURCEPREFIX + getUserDataSourceSession().getUserDataSourceId(
						getAdmin(), resource.substring(AvailableAccessRules.USERDATASOURCEPREFIX.length()));
			} else {
				return AvailableAccessRules.USERDATASOURCEPREFIX + getUserDataSourceSession().getUserDataSourceId(
						getAdmin(), resource.substring(AvailableAccessRules.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/'))) +
						resource.substring(resource.lastIndexOf('/'));
			}
		}
		return resource;
	}
}
