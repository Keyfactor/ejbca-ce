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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * CRUD session bean for managing RoleMemberData objects
 * 
 * @version $Id$
 *
 */
public interface RoleMemberSession {

    /**
     * Returns the Role Member with the given ID, or null if it does not exist.
     * @throws AuthorizationDeniedException if not authorized to the Role or the CA in the RoleMember object.
     */
    RoleMember getRoleMember(AuthenticationToken authenticationToken, int roleMemberId) throws AuthorizationDeniedException;

}
