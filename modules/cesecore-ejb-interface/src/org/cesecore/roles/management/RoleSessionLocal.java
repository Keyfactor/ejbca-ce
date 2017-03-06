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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

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
    
}
