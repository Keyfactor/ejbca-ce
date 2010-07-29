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

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.cli.BaseCommand;

/**
 * Base for Admins commands, contains common functions for Admins operations
 * 
 */
public abstract class BaseAdminsCommand extends BaseCommand {

    protected static final String MAINCOMMAND = "admins";

    private RaAdminSessionRemote raAdminSession = ejb.getRAAdminSession();
    private CAAdminSessionRemote caAdminSession = ejb.getCAAdminSession();
    private UserDataSourceSessionRemote userDataSourceSession = ejb.getUserDataSourceSession();
    
    protected String getParsedAccessRule(String resource) throws NumberFormatException, RemoteException {
        // Check if it is a profile rule, then replace profile id with profile
        // name.
        if (resource.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + raAdminSession.getEndEntityProfileName(getAdmin(), Integer.parseInt(resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX
                                .length())));
            } else {
                String tmpString = resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + raAdminSession.getEndEntityProfileName(getAdmin(), Integer.parseInt(tmpString.substring(0, tmpString.indexOf('/'))))
                        + tmpString.substring(tmpString.indexOf('/'));
            }
        }
        // Check if it is a CA rule, then replace CA id with CA name.
        if (resource.startsWith(AccessRulesConstants.CAPREFIX)) {
            Map caIdToNameMap = caAdminSession.getCAIdToNameMap(getAdmin());
            if (resource.lastIndexOf('/') < AccessRulesConstants.CAPREFIX.length()) {
                return AccessRulesConstants.CAPREFIX + caIdToNameMap.get(new Integer(resource.substring(AccessRulesConstants.CAPREFIX.length())));
            } else {
                return AccessRulesConstants.CAPREFIX
                        + caIdToNameMap.get(new Integer(resource.substring(AccessRulesConstants.CAPREFIX.length(), resource.lastIndexOf('/'))))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a User Data Source rule, then replace User Data Source
        // id with User Data Source name.
        if (resource.startsWith(AccessRulesConstants.USERDATASOURCEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.USERDATASOURCEPREFIX.length()) {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + userDataSourceSession.getUserDataSourceName(getAdmin(),
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length())));
            } else {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + userDataSourceSession.getUserDataSourceName(getAdmin(),
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/'))))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        return resource;
    }

    protected String getOriginalAccessRule(String resource) throws NumberFormatException, RemoteException {
        // Check if it is a profile rule, then replace profile id with profile
        // name.
        if (resource.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + raAdminSession.getEndEntityProfileId(getAdmin(), resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()));
            } else {
                String tmpString = resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + raAdminSession.getEndEntityProfileId(getAdmin(), tmpString.substring(0, tmpString.indexOf('/')))
                        + tmpString.substring(tmpString.indexOf('/'));
            }
        }
        // Check if it is a CA rule, then replace CA id with CA name.
        if (resource.startsWith(AccessRulesConstants.CAPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.CAPREFIX.length()) {
                return AccessRulesConstants.CAPREFIX
                        + caAdminSession.getCAInfo(getAdmin(), resource.substring(AccessRulesConstants.CAPREFIX.length())).getCAId();
            } else {
                return AccessRulesConstants.CAPREFIX
                        + caAdminSession.getCAInfo(getAdmin(), resource.substring(AccessRulesConstants.CAPREFIX.length(), resource.lastIndexOf('/'))).getCAId()
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a User Data Source rule, then replace User Data Source
        // id with User Data Source name.
        if (resource.startsWith(AccessRulesConstants.USERDATASOURCEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.USERDATASOURCEPREFIX.length()) {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + userDataSourceSession.getUserDataSourceId(getAdmin(), resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length()));
            } else {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + userDataSourceSession.getUserDataSourceId(getAdmin(),
                                resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/')))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        return resource;
    }
}
