/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.roles.management;

import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;

/**
 * The Roles Management interface manages the list of roles and which access rules applies to defined roles. The roles interface also manages the list
 * of Subjects who are part of the roles. There are three distinct methods to this interface:
 * <ul>
 * <li>
 * managing the roles, which by default are only a name not associated with anything.</li>
 * <li>
 * managing access rules, which makes a role into something that defines what subject can do.</li>
 * <li>
 * managing subjects, which makes users part of the role thus giving them the access rights defined by the access rules of the role.</li>
 * </ul>
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Roles_Management}
 * 
 * @version $Id$
 */
@Deprecated
@Local
public interface RoleManagementSessionLocal {

    /**
     * @return a Collection of role names authorized to the resource,
     */
    List<AdminGroupData> getAuthorizedRoles(String resource, boolean requireRecursive);


    /**
     * Adds a legacy role.
     * 
     * @param authenticationToken only used for audit logging
     * @param roleName Name of the role
     * @throws RoleExistsException If role by that name already exists.
     * @return the {@link AdminGroupData} that was created
     */
    AdminGroupData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException;

    /**
     * Removes a legacy role if present. Will also remove all associated access rules and user aspects.
     * 
     * @param authenticationToken only used for audit logging
     * @param roleName The name of the role to remove.
     */
    void deleteIfPresentNoAuth(AuthenticationToken authenticationToken, String roleName);

    /**
     * Associates a list of access rules to a role. If the given role already exists, replace it.
     * 
     * @param authenticationToken only used for audit logging
     * @param role The role
     * @param accessRules A collection of access rules. 
     * @throws RoleNotFoundException if the role does not exist
     * 
     * @return the merged {@link AdminGroupData} with the new access rules
     */
    AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException;

    /**
     * Removes the given access rules from a role.
     * 
     * @param authenticationToken only used for audit logging
     * @param role The role.
     * @param accessRules A collection of access rules. If these rules haven't been removed from persistence, they will be here.
     * @throws RoleNotFoundException if the role does not exist
     * @return the merged {@link AdminGroupData} with the new access rules
     */
    AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException;
    
    /**
     * Gives the collection of subjects the given role. If the subject already exists, update it with the new value.
     * 
     * @param authenticationToken only used for audit logging
     * @param subjects A collection of subjects
     * @param role The role to give.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the merged {@link AdminGroupData} with the new subjects
     * 
     *             TODO: Rename this method AddAccessUserAspectsToRole
     */
    AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessUserAspectData> subjects)
            throws RoleNotFoundException;

    /**
     * Retrieves a list of the roles which the given subject is authorized to edit, by checking if that subject has rights to the CA's behind all
     * access user aspects in that role, and all CA-based rules
     * 
     * @param authenticationToken An authentication token for the subject
     * @return a list of roles which the subject is authorized to edit.
     */
    Collection<AdminGroupData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken);

    /**
     * Never use this method except during upgrade.
     * 
     * @deprecated Remove this method once 4.0.x -> 5.0.x support has been dropped. 
     */
    AdminGroupData replaceAccessRulesInRoleNoAuth(final AuthenticationToken authenticationToken, final AdminGroupData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException;

}
