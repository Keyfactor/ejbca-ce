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

import javax.ejb.Local;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Local interface for RoleAccess
 * 
 * @version $Id$
 *
 */
@Deprecated
@Local
public interface RoleAccessSessionLocal extends RoleAccessSession {

    /**
     * Get a list of role that match the given authentication token, i.e. roles that the authentication token is part of
     * 
     * @param authenticationToken a token to match with
     * @return a list of role that match the given authentication token, can be an empty list but not null
     * @throws AuthenticationFailedException if any errors were found with the authentication token
     */
    List<String> getRolesMatchingAuthenticationToken(final AuthenticationToken authenticationToken) throws AuthenticationFailedException;
}
