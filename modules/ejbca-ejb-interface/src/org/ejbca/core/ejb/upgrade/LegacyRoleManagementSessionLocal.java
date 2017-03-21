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
package org.ejbca.core.ejb.upgrade;

import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;

/**
 * The legacy Roles Management interface manages the list of roles and which access rules applies to defined roles. The roles interface also manages the list
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
public interface LegacyRoleManagementSessionLocal {

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
    void deleteRole(AuthenticationToken authenticationToken, String roleName);

    /**
     * Associates a list of access rules to a role. If the given role already exists, replace it.
     * 
     * @param authenticationToken only used for audit logging
     * @param role The role
     * @param accessRules A collection of access rules. 
     * 
     * @return the merged {@link AdminGroupData} with the new access rules
     */
    AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessRuleData> accessRules);

    /**
     * Gives the collection of subjects the given role. If the subject already exists, update it with the new value.
     * 
     * @param authenticationToken only used for audit logging
     * @param subjects A collection of subjects
     * @param role The role to give.
     * @return the merged {@link AdminGroupData} with the new subjects
     */
    AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, AdminGroupData role, Collection<AccessUserAspectData> subjects);

    /**
     * Retrieves all roles in the database..
     * 
     * @return all the roles in the database.
     */
    List<AdminGroupData> getAllRoles();


    /**
     * Finds a specific role by name.
     * 
     * @param roleName Name of the sought role.
     * @return The sought roll, null if not found
     */
    AdminGroupData getRole(String roleName);


    /**
     * Creates a super administrator role and a default CLI user. A role and default CLI user is needed in order
     * to do operations with the CLI (command line interface).  
     */
    void createSuperAdministrator();

    /**
     * Add the grantedAccessRules to the role when conditions are met.
     * 
     * @param authenticationToken only used for audit logging
     * @param skipWhenRecursiveAccessTo ignore all roles that have recursive access to the rule
     * @param requiredAccessRules all access rules that the role must be authorized to in order to extend the grants (if a grantedAccessRules is present here it is not required)
     * @param grantedAccessRules the access rules to grant
     * @param grantedAccessRecursive true if the access rules should be granted as recursive
     */
    void addAccessRuleDataToRolesWhenAccessIsImplied(AuthenticationToken authenticationToken, String skipWhenRecursiveAccessTo, List<String> requiredAccessRules,
            List<String> grantedAccessRules, boolean grantedAccessRecursive);

    /**
     * Set the tokenType to X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE if it was not set before.
     * 
     * @param authenticationToken only used for audit logging
     */
    void setTokenTypeWhenNull(AuthenticationToken authenticationToken);

    /**
     * Delete ALL legacy AdminGroupData, AdminEntityData and AccessRuleData.
     * 
     * @param authenticationToken only used for audit logging
     */
    void deleteAllRoles(AuthenticationToken authenticationToken);
}
