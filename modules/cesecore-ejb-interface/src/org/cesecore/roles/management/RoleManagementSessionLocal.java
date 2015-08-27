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
import org.cesecore.roles.RoleData;

/**
 * Local interface for RoleManagementSession.
 * 
 * @version $Id$
 *
 */
@Local
public interface RoleManagementSessionLocal extends RoleManagementSession {

    /**
     * @return a Collection of role names authorized to the resource,
     */
    List<RoleData> getAuthorizedRoles(String resource, boolean requireRecursive);
    
    /**
     * @return a Collection of role names authorized to the resource,
     * it also only returns only the roles the administrator is authorized to edit.
     */
    List<RoleData> getAuthorizedRoles(AuthenticationToken admin, String resource);
    
    /**
     * @param requireRecursive if recursive access is required for the resource
     * 
     * @return a Collection of role names authorized to the resource,
     * it also only returns only the roles the administrator is authorized to edit.
     */
    List<RoleData> getAuthorizedRoles(AuthenticationToken admin, String resource, boolean requireRecursive);

}
