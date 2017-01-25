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
package org.cesecore.roles.member;

import java.util.List;

/**
 * CRUD session bean for managing RoleMemberData objects
 * 
 * @version $Id$
 *
 */
public interface RoleMemberSession {

    /**
     * Finds an RoleMemberData by its primary key.
     * 
     * @param primaryKey
     *            Primary key of the sought instance.
     * @return the sought RoleMember, otherwise null. .
     */
    RoleMember findRoleMember(final int primaryKey);

    /**
     * 
     * @param roleId the ID of a role
     * @return a list of members to the given role
     */
    List<RoleMember> findRoleMemberByRoleId(int roleId);


}
