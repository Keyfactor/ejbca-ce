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

import jakarta.ejb.Local;

import org.cesecore.dto.RoleDataDto;

/**
 * Interface for low level Role operations.
 * 
 * @version $Id$
 */
@Local
public interface RoleDataSessionLocal extends RoleDataSession {

    /**
     * @return all roles
     */
    List<RoleDataDto> getAllRoles();

    /**
     * @return a role by its unique id or null if the role does not exist
     */
    RoleDataDto getRole(int id);

    /**
     * Find a role in the database from the unique roleName and nameSpace combination.
     *
     * @param roleName
     * @param nameSpace
     * @return the role or null if none was found
     */
    RoleDataDto getRole(String roleName, String nameSpace);

    /**
     * Delete a role from the database (currently not affecting any role members)
     * @param roleId
     * @return true if a change was made to the database (the row was deleted)
     */
    boolean deleteRoleNoAuthorizationCheck(int roleId);

    /** 
     * Persist (creating a new row if needed) the role to the database.
     * 
     * @return persisted version of the role
     */
    RoleDataDto persistRole(RoleDataDto role);
}
