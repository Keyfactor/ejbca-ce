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
 * 
 */
@Deprecated
public interface RoleManagementSession {

    /**
     * Adds a role
     * 
     * @param roleName Name of the role
     * @throws RoleExistsException If role by that name already exists.
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the {@link AdminGroupData} that was created
     */
    AdminGroupData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException, AuthorizationDeniedException;

    /**
     * Remove a role.
     * 
     * @param authenticationToken An authentication token.
     * @param roleName The name of the role to remove.
     * @throws RoleNotFoundException if role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    void remove(AuthenticationToken authenticationToken, String roleName) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes a known role. Will also remove all associated access rules and user aspects.
     * 
     * @param authenticationToken An authentication token.
     * @param role the role to remove.
     * @throws RoleNotFoundException if role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    void remove(AuthenticationToken authenticationToken, AdminGroupData role) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Renames a role.
     * 
     * @param role The name of the old role to change.
     * @param newName The new name of the role.
     * @throws RoleExistsException If the new role name already exists.
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the new {@link AdminGroupData} that was the result of the rename
     */
    AdminGroupData renameRole(AuthenticationToken authenticationToken, String role, String newName) throws RoleExistsException,
            AuthorizationDeniedException;

    /**
     * Renames a role.
     * 
     * @param role The role to change.
     * @param newName The new name of the role.
     * @throws RoleExistsException If the new role name already exists.
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the new {@link AdminGroupData} that was the result of the rename
     */
    AdminGroupData renameRole(AuthenticationToken authenticationToken, AdminGroupData role, String newName) throws RoleExistsException,
            AuthorizationDeniedException;

    /**
     * Associates a list of access rules to a role. If the given role already exists, replace it.
     * 
     * @param role The role
     * @param accessRules A collection of access rules. 
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * 
     * @return the merged {@link AdminGroupData} with the new access rules
     */
    AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes the given access rules from a role.
     * 
     * @param role The role.
     * @param accessRules A collection of access rules. If these rules haven't been removed from persistence, they will be here.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the merged {@link AdminGroupData} with the new access rules
     */
    AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AuthorizationDeniedException;
    
    /**
    * Removes the given access rules from a role.
    * 
    * @param role The role.
    * @param accessRules A collection of strings. These rules will be looked up and removed from persistence.
    * @throws RoleNotFoundException if the role does not exist
    * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
    * @return the merged {@link AdminGroupData} with the new access rules
    */
   AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, AdminGroupData role, List<String> accessRuleNames)
           throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Gives the collection of subjects the given role. If the subject already exists, update it with the new value.
     * 
     * @param subjects A collection of subjects
     * @param role The role to give.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the merged {@link AdminGroupData} with the new subjects
     * 
     *             TODO: Rename this method AddAccessUserAspectsToRole
     */
    AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessUserAspectData> subjects)
            throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes the role from the list of subjects.
     * 
     * @param subjects A collection of subjects.
     * @param role The role to remove.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * @return the merged {@link AdminGroupData} with the new subjects
     */
    AdminGroupData removeSubjectsFromRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessUserAspectData> subjects)
            throws RoleNotFoundException, AuthorizationDeniedException;
    
    
    /**
     * Retrieves a list of the roles which the given subject is authorized to edit, by checking if that subject has rights to the CA's behind all
     * access user aspects in that role, and all CA-based rules
     * 
     * @param authenticationToken An authentication token for the subject
     * @return a list of roles which the subject is authorized to edit.
     */
    Collection<AdminGroupData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken);
    
    /**
     * Examines if the current user is authorized to edit a role. It checks all access user aspects (and checks access to the CA's issuing them), as
     * well as all CA based rules within the role.
     * 
     * Will not accept recursive accept values. 
     * 
     * @param authenticationToken an authentication token for the subject to check
     * @param role the role to check against.
     * @return true if the subject has access.
     */
    boolean isAuthorizedToRole(AuthenticationToken authenticationToken, AdminGroupData role);
    
    /**
     * Checks that the given {@link AuthenticationToken} has access to all the rules it's planning use. 
     * 
     * @param authenticationToken an authentication token
     * @param rules a list of rules to check against
     * @return true if the authentication token had access to all the rules, false otherwise.
     */
    boolean isAuthorizedToRules(AuthenticationToken authenticationToken, Collection<AccessRuleData> rules);
 
    /**
     * Replaces the existing access rules in the given role by removing the old ones and adding the list of new ones.
     * 
     * @param authenticationToken for authorization purposes.
     * @param role the role in question.
     * @param accessRules A Collection of access rules to replace with.
     * @return the merged {@link AdminGroupData} with the new rules
     * @throws AuthorizationDeniedException if authorization was denied.
     * @throws RoleNotFoundException if the supplied role was not found in persistence. 
     */
    AdminGroupData replaceAccessRulesInRole(final AuthenticationToken authenticationToken, final AdminGroupData role, final Collection<AccessRuleData> accessRules)
            throws AuthorizationDeniedException, RoleNotFoundException;
}
