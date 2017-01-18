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
package org.cesecore.roles.access;

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.AdminGroupData;

/**
 * Implementations of this bean give access to RoleData objects.
 * 
 * @version $Id$
 * 
 */
@Deprecated
public interface RoleAccessSession {

    /**
     * Retrieves all roles in the database..
     * 
     * @return all the roles in the database.
     */
    List<AdminGroupData> getAllRoles();
    
    /**
     * 
     * @param authenticationToken an authentication token
     * @return a list of all roles the current user is authorized to, based on CAs and access rules. Will sort them by name. 
     */
    List<AdminGroupData> getAllAuthorizedRoles(AuthenticationToken authenticationToken);

    /**
     * Finds a RoleData object by its primary key.
     * 
     * @param primaryKey
     *            The primary key.
     * @return the found entity instance or null if the entity does not exist.
     */
    AdminGroupData findRole(final Integer primaryKey);

    /**
     * Finds a specific role by name.
     * @param roleName
     *            Name of the sought role.
     * 
     * @return The sought roll, null if not found
     */
    AdminGroupData findRole(final String roleName);
}
