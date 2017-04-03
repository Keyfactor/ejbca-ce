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

import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;

/**
 * Local interface for Role management operations.
 * 
 * @version $Id$
 */
@Local
public interface RoleSessionLocal extends RoleSession {

    /**
     * Checks if the administrator is allowed to add/edit/remove role members from role with the given ID.
     * Note that role member objects may reference a CA also, which must be checked for access as well. 
     */
    void assertAuthorizedToRoleMembers(AuthenticationToken authenticationToken, int roleId, boolean requireEditAccess) throws AuthorizationDeniedException;

    /** @return a List of Roles the caller is a member of (without taking nesting into account) */
    List<Role> getRolesAuthenticationTokenIsMemberOf(AuthenticationToken authenticationToken);

    /** @return a list of all Roles that have access to the resource and the caller is allowed to see */
    List<Role> getAuthorizedRolesWithAccessToResource(AuthenticationToken authenticationToken, String resource);

    /** 
     * Update Role access rules and optionally any RoleMember relating to the CA ID.
     * 
     * Authorization to perform this operation should be checked by the caller and implied by the type of operation.
     * 
     * @param keepOldAccessRule when true, the /ca/(caIdOld)/ rule will be kept as well.
     * @param updateRoleMembers update the RoleMember.tokenIssuerId for members issued by this CA
     */
    boolean updateCaId(int caIdOld, int caIdNew, boolean keepOldAccessRule, boolean updateRoleMembers);

    /** @throws AuthorizationDeniedException if changing this role would affect the access granted to the specified authenticationToken. */
    void assertNonImportantRoleMembership(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException;
}
