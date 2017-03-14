/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.roles;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;

/**
 * Base for Roles commands, contains common functions for Roles operations
 */
public abstract class BaseRolesCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(BaseRolesCommand.class);

    private Map<String,String> resourceNameToResourceMap = null;
    private Map<String,String> resourceToResourceNameMap = null;

    private static Set<String[]> commandAliases = new HashSet<String[]>();
    static {
        commandAliases.add(new String[] { "admins" });
        try {
            Class.forName(X500PrincipalAccessMatchValue.class.getName());
            Class.forName(CliUserAccessMatchValue.class.getName());
        } catch (ClassNotFoundException e) {
            log.error("Failure during match value initialization", e);
        }
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "roles" };
    }

    @Override
    public Set<String[]> getCommandPathAliases() {
        return commandAliases;
    }

    /**
     * 
     * @throws AuthorizationDeniedException if rule was for a CA that CLI user isn't authorized to.
     * @throws CADoesntExistsException if rule was for a CA that doesn't exist.
     */
    protected String getParsedAccessRule(AuthenticationToken authenticationToken, String resource) throws AuthorizationDeniedException,
            CADoesntExistsException {
        // Check if it is a profile rule, then replace profile id with profile
        // name.
        if (resource.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(
                                Integer.parseInt(resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length())));
            } else {
                String tmpString = resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(
                                Integer.parseInt(tmpString.substring(0, tmpString.indexOf('/')))) + tmpString.substring(tmpString.indexOf('/'));
            }
        }
        // Check if it is a CA rule, then replace CA id with CA name.
        if (resource.startsWith(StandardRules.CAACCESS.resource())) {
            if (resource.lastIndexOf('/') < StandardRules.CAACCESS.resource().length()) {
                final int caid = Integer.valueOf(resource.substring(StandardRules.CAACCESS.resource().length()));
                String caname = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caid).getName();

                return StandardRules.CAACCESS.resource() + caname;
            } else {
                final int caid = Integer.valueOf(resource.substring(StandardRules.CAACCESS.resource().length(), resource.lastIndexOf('/')));
                final String caname = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, caid).getName();
                return StandardRules.CAACCESS.resource() + caname + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a User Data Source rule, then replace User Data Source
        // id with User Data Source name.
        if (resource.startsWith(AccessRulesConstants.USERDATASOURCEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.USERDATASOURCEPREFIX.length()) {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getUserDataSourceName(authenticationToken,
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length())));
            } else {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getUserDataSourceName(authenticationToken,
                                Integer.parseInt(resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/'))))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        return resource;
    }

    protected String getOriginalAccessRule(AuthenticationToken authenticationToken, String resource) throws CADoesntExistsException,
            AuthorizationDeniedException, EndEntityProfileNotFoundException {
        // Check if it is a profile rule, then replace profile id with profile
        // name.
        if (resource.startsWith(AccessRulesConstants.ENDENTITYPROFILEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()) {
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileId(
                                resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length()));
            } else {
                String tmpString = resource.substring(AccessRulesConstants.ENDENTITYPROFILEPREFIX.length());
                return AccessRulesConstants.ENDENTITYPROFILEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileId(
                                tmpString.substring(0, tmpString.indexOf('/'))) + tmpString.substring(tmpString.indexOf('/'));
            }
        }
        // Check if it is a CA rule, then replace CA id with CA name.
        if (resource.startsWith(StandardRules.CAACCESS.resource())) {
            if (resource.lastIndexOf('/') < StandardRules.CAACCESS.resource().length()) {
                return StandardRules.CAACCESS.resource()
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class)
                                .getCAInfo(authenticationToken, resource.substring(StandardRules.CAACCESS.resource().length())).getCAId();
            } else {
                return StandardRules.CAACCESS.resource()
                        + EjbRemoteHelper.INSTANCE
                                .getRemoteSession(CaSessionRemote.class)
                                .getCAInfo(authenticationToken,
                                        resource.substring(StandardRules.CAACCESS.resource().length(), resource.lastIndexOf('/'))).getCAId()
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        // Check if it is a User Data Source rule, then replace User Data Source
        // id with User Data Source name.
        if (resource.startsWith(AccessRulesConstants.USERDATASOURCEPREFIX)) {
            if (resource.lastIndexOf('/') < AccessRulesConstants.USERDATASOURCEPREFIX.length()) {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getUserDataSourceId(authenticationToken,
                                resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length()));
            } else {
                return AccessRulesConstants.USERDATASOURCEPREFIX
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(UserDataSourceSessionRemote.class).getUserDataSourceId(authenticationToken,
                                resource.substring(AccessRulesConstants.USERDATASOURCEPREFIX.length(), resource.lastIndexOf('/')))
                        + resource.substring(resource.lastIndexOf('/'));
            }
        }
        return resource;
    }

    protected abstract Logger getLogger();

    public Map<String, String> getResourceNameToResourceMap() {
        if (resourceNameToResourceMap==null) {
            final Map<String,String> authorizedResourcesMap = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class).
                    getAllResources(getAuthenticationToken(), false);
            resourceNameToResourceMap = new HashMap<>();
            for (final Entry<String,String> entry: authorizedResourcesMap.entrySet()) {
                resourceNameToResourceMap.put(entry.getValue(), entry.getKey());
            }
        }
        return resourceNameToResourceMap;
    }

    public Map<String, String> getResourceToResourceNameMap() {
        if (resourceToResourceNameMap==null) {
            resourceToResourceNameMap = EjbRemoteHelper.INSTANCE.getRemoteSession(AuthorizationSystemSessionRemote.class).
                    getAllResources(getAuthenticationToken(), false);
        }
        return resourceToResourceNameMap;
    }
}
