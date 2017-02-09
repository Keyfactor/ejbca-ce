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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;

/**
 * Common interface for Role management operations.
 * 
 * @version $Id$
 */
public interface RoleSession {

    /**
     * Store the provided role. If the role id is 0, a new Id will be assigned and the role will be created.
     * 
     * @return the persisted version of the object including an assigned id and normalized access rules.
     * @throws RoleExistsException if provided role's nameSpace and roleName combination is used by another role
     * @throws AuthorizationDeniedException if the caller is not authorized to store the role
     */
    Role persistRole(AuthenticationToken authenticationToken, Role role) throws RoleExistsException, AuthorizationDeniedException;

    /**
     * Deletes the role with the requested id.
     * 
     * @throws AuthorizationDeniedException if the caller is not authorized to see this role and edit roles in general
     * @return true if a change was made to the database
     */
    boolean deleteRoleIdempotent(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException;

    /**
     * @return the Role for the specified id or null if no such role exists
     * @throws AuthorizationDeniedException the caller is not authorized to see this role (leaks that a role with this id exists)
     */
    Role getRole(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException;

    /**
     * @param authenticationToken the callers AuthenticationToken
     * @param nameSpace the namespace the role lives in that together with roleName is a globally unique combination. null (or empty String) is a valid namespace.
     * @param roleName human readable name of the role
     * @return the Role for the specified id or null if no such role exists
     * @throws AuthorizationDeniedException the caller is not authorized to see this role (leaks that a role with this id exists)
     */
    Role getRole(AuthenticationToken authenticationToken, String nameSpace, String roleName) throws AuthorizationDeniedException;
    
    /**
     * Returns a list of all roles that the gives administrator is allowed to see. 
     * @param authenticationToken Administrator.
     * @return List of authorized roles. May be empty, but never null.
     */
    List<Role> getAuthorizedRoles(AuthenticationToken authenticationToken);
}
