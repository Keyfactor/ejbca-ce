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
package org.cesecore.authorization;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Main interface for checking authorization. This interface makes use of roles and entity authentication to verify authorization.
 * 
 * @version $Id$
 */
public interface AuthorizationSession {

    /**
     * Checks if the current user is authorized for the given resource.
     * Will create audit log. 
     * 
     * @param authenticationToken The {@link AuthenticationToken} to check access for.
     * @param resources String identifier(s) of the resource(s) in question.
     * @return true if user is authorized, false if not.
     */
    boolean isAuthorized(AuthenticationToken authenticationToken, String...resources);

    /**
     * Checks if the current user is authorized for the given resource.
     * Will not create any audit log. 
     * 
     * @param authenticationToken The {@link AuthenticationToken} to check access for.
     * @param resources String identifier(s) of the resource(s) in question.
     * @return true if user is authorized, false if not.
     */
    boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String...resources);
}
