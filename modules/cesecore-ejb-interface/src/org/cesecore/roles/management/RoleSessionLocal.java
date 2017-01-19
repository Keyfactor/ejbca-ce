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
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;

/**
 * Local interface for Role management operations.
 * 
 * @version $Id$
 */
@Local
public interface RoleSessionLocal extends RoleSession {

    /** @return all roles */
    List<Role> getAllRoles();

    /** @return a role by its unique id */
    Role getRole(int id);

    /**
     * Find a role in the database from the unique roleName and nameSpace combination.
     * @param roleName
     * @param nameSpace
     * @return the role or null if none was found
     */
    Role getRole(String roleName, String nameSpace);

    /**
     * Persist the role to the database.
     * If the role does not exist, it will be created.
     * If the role exists under another name, it will be renamed.
     * 
     * @param authenticationToken used for audit logging
     * @param role is the role to persist
     * @return the Role parameter enriched with assigned Id and normalized access rules
     * @throws RoleExistsException if a different role exists with the same name under the same namespace.
     */
    Role persistRoleNoAuthorizationCheck(AuthenticationToken authenticationToken, Role role) throws RoleExistsException;

    /**
     * Delete a role from the database (currently not affecting any role members)
     * @param roleId
     * @return true if a change was made to the database (the row was deleted)
     */
    boolean deleteRoleNoAuthorizationCheck(int roleId);

}
