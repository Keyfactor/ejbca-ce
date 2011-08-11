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

package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSession;
import org.cesecore.roles.management.RoleManagementSession;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * A class handling the authorization data.
 * 
 * FIXME: Rename the methods in this class to fit what they actually do
 * 
 * @version $Id$
 */
public class AuthorizationDataHandler implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(AuthorizationDataHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private AccessControlSessionLocal authorizationsession;
    private ComplexAccessControlSessionLocal complexAccessControlSession;
    private RoleAccessSession roleAccessSession;
    private RoleManagementSession roleManagementSession;
    private AuthenticationToken administrator;
    private Collection<RoleData> authorizedRoles;
    private InformationMemory informationmemory;

    /** Creates a new instance of ProfileDataHandler */
    public AuthorizationDataHandler(AuthenticationToken administrator, InformationMemory informationmemory, RoleAccessSession roleAccessSession,
            RoleManagementSession roleManagementSession, AccessControlSessionLocal authorizationsession, ComplexAccessControlSessionLocal complexAccessControlSession) {
        this.roleManagementSession = roleManagementSession;
        this.roleAccessSession = roleAccessSession;
        this.authorizationsession = authorizationsession;
        this.administrator = administrator;
        this.informationmemory = informationmemory;
        this.complexAccessControlSession = complexAccessControlSession;
    }

    /**
     * Method to check if a admin is authorized to a resource
     * 
     * @param admin information about the administrator to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(AuthenticationToken admin, String resource) {
        return authorizationsession.isAuthorized(admin, resource);
    }

    /**
     * Method to check if a admin is authorized to a resource without performing any logging.
     * 
     * @param admin information about the administrator to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(AuthenticationToken admin, String resource) {
        return authorizationsession.isAuthorizedNoLog(admin, resource);
    }

    /**
     * Method to add a new role to the administrator privileges data.
     * 
     * @throws RoleExistsException
     */
    public void addRole(String name) throws AuthorizationDeniedException, RoleExistsException {
        // Authorized to edit administrative privileges
        if (!authorizationsession.isAuthorized(administrator, "/system_functionality/edit_administrator_privileges")) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                    "/system_functionality/edit_administrator_privileges", null);
            throw new AuthorizationDeniedException(msg);
        }
        roleManagementSession.create(administrator, name);
        informationmemory.administrativePriviledgesEdited();
        this.authorizedRoles = null;
    }

    /**
     * Method to remove a role.
     * 
     * @throws RoleNotFoundException
     */
    public void removeRole(String name) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(roleAccessSession.findRole(name));
        roleManagementSession.remove(administrator, name);
        informationmemory.administrativePriviledgesEdited();
        this.authorizedRoles = null;
    }

    /**
     * Method to rename a role.
     * 
     * @throws RoleExistsException
     */
    public void renameRole(String oldname, String newname) throws AuthorizationDeniedException, RoleExistsException {
        authorizedToEditAdministratorPrivileges(roleAccessSession.findRole(oldname));
        roleManagementSession.renameRole(administrator, oldname, newname);
        informationmemory.administrativePriviledgesEdited();
        this.authorizedRoles = null;
    }

    /**
     * Method returning a Collection of authorized roles. Only the fields role name and CA id is filled in these objects.
     */
    public Collection<RoleData> getRoles() {
        if (this.authorizedRoles == null) {
            // FIXME: This method should be amended to access control
            this.authorizedRoles = complexAccessControlSession.getAllRolesAuthorizedToEdit(administrator);
        }
        return this.authorizedRoles;
    }

    /**
     * Returns the given role with it's authorization data
     * 
     * @throws AuthorizationDeniedException if administrator isn't authorized to access role.
     */
    public RoleData getRole(String roleName) throws AuthorizationDeniedException {
        RoleData role = roleAccessSession.findRole(roleName);
        authorizedToEditAdministratorPrivileges(role);
        return roleAccessSession.findRole(roleName);
    }

    /**
     * Method to add a Collection of AccessRule to an role.
     * 
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA or when administrator tries to add access rules she
     *             isn't authorized to.
     * @throws RoleNotFoundException
     * @throws AccessRuleNotFoundException
     */
    public void addAccessRules(String roleName, Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException,
            AccessRuleNotFoundException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(roleAccessSession.findRole(roleName));
        authorizedToAddAccessRules(roleName, accessRules);
        roleManagementSession.addAccessRulesToRole(administrator, roleAccessSession.findRole(roleName), accessRules);
        informationmemory.administrativePriviledgesEdited();
    }

    /**
     * Method to remove an collection of access rules from a role.
     * 
     * @param accessrules a Collection of AccessRuleData containing accesss rules to remove.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     * @throws RoleNotFoundException
     */
    public void removeAccessRules(String roleName, Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(roleAccessSession.findRole(roleName));
        roleManagementSession.removeAccessRulesFromRole(administrator, roleAccessSession.findRole(roleName), accessRules);
        informationmemory.administrativePriviledgesEdited();
    }

    /**
     * Method to replace an collection of access rules in a role.
     * 
     * @param accessrules a Collection of String containing accesssrules to replace.
     * @throws AuthorizationDeniedException when administrator is't authorized to edit this CA.
     * @throws RoleNotFoundException 
     */
    public void replaceAccessRules(String rolename, Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(roleAccessSession.findRole(rolename));
        roleManagementSession.replaceAccessRulesInRole(administrator, roleAccessSession.findRole(rolename), accessRules);
        informationmemory.administrativePriviledgesEdited();
    }

    /**
     * Method returning all the available access rules authorized to administrator to manage.
     * 
     * @returns a Collection of strings with available access rules.
     */
    public Collection<String> getAvailableAccessRules() {
        return this.informationmemory.getAuthorizedAccessRules();
    }

    /**
     * Method to add a Collection of AdminEntity to an role.
     * 
     * @throws AuthorizationDeniedException if administrator isn't authorized to edit CAs administrative privileges.
     * @throws RoleNotFoundException 
     */
    public void addAdminEntities(RoleData role, Collection<AccessUserAspectData> subjects) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(role);
        roleManagementSession.addSubjectsToRole(administrator, role, subjects);
        informationmemory.administrativePriviledgesEdited();
    }

    /**
     * Method to remove a Collection of AdminEntity from an role.
     * 
     * @throws AuthorizationDeniedException if administrator isn't authorized to edit CAs administrative privileges.
     * @throws RoleNotFoundException 
     */
    public void removeAdminEntities(RoleData role, Collection<AccessUserAspectData> subjects) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditAdministratorPrivileges(role);
        roleManagementSession.removeSubjectsFromRole(administrator, role, subjects);
        informationmemory.administrativePriviledgesEdited();
    }

    private void authorizedToEditAdministratorPrivileges(RoleData role) throws AuthorizationDeniedException {
        // Authorized to edit administrative privileges
        if (!authorizationsession.isAuthorizedNoLog(administrator, AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                    AccessRulesConstants.REGULAR_EDITADMINISTRATORPRIVILEDGES, null);
            throw new AuthorizationDeniedException(msg);
        }
        // Authorized to group
        if (!complexAccessControlSession.isAuthorizedToEditRole(administrator, role)) {
            throw new AuthorizationDeniedException("Admin " + administrator + " not authorized to group " + role);
        }
        // Check if admin group is among available admin groups
        boolean exists = false;
        for (RoleData next : complexAccessControlSession.getAllRolesAuthorizedToEdit(administrator)) {
            if (next.equals(role)) {
                exists = true;
            }
        }
        if (!exists) {
            if (log.isDebugEnabled()) {
                log.debug("role " + role + " not among authorized roles.");
            }
            throw new AuthorizationDeniedException("role " + role + " not among authorized roles.");
        }
    }

    private void authorizedToAddAccessRules(String roleName, Collection<AccessRuleData> accessrules) throws AuthorizationDeniedException {
        for (AccessRuleData accessRule : accessrules) {
            if (!this.informationmemory.getAuthorizedAccessRules().contains(accessRule)) {
                throw new AuthorizationDeniedException("Accessruleset contained non authorized access rules");
            }
        }
    }
}
