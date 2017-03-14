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

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.Role;

/**
 * Remote interface for Role management operations.
 * 
 * @version $Id$
 */
@Remote
public interface RoleSessionRemote extends RoleSession {

    /** @return a List of Roles the authenticationTokenToCheck is a member of (without taking nesting into account) */
    List<Role> getRolesAuthenticationTokenIsMemberOfRemote(AuthenticationToken authenticationTokenForAuhtorization, AuthenticationToken authenticationTokenToCheck);
}
