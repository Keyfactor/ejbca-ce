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
package org.cesecore.authorization.control;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessSet;

/**
 * Main interface for checking authorization. This interface makes use of roles and entity authentication to verify authorization.
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Access_Control_2}
 * 
 * @version $Id$
 * 
 */
@Deprecated
public interface AccessControlSession {

    /**
     * Checks if the current user is authorized for the given resource.
     * 
     * Will by default accept recursive and non-recursive accept values. 
     * 
     * @param resources String identifier(s) of the resource(s) in question.
     * @return True if user is authorized, false if not.
     */
    boolean isAuthorized(AuthenticationToken authenticationToken, String... resources);
    
    /**
     * Checks if the current user is authorized for the given resource.
     * 
     * @param requireRecursive true if only accept recursive values should be accepted.
     * @param resources String identifier(s) of the resource(s) in question.
     * @return True if user is authorized, false if not.
     */
    boolean isAuthorized(AuthenticationToken authenticationToken, boolean requireRecursive, String... resources);


    /**
     * Checks if the current user is authorized for the given resource.
     * Will not create any audit log. 
     * 
     * Will by default accept recursive and non-recursive accept values. 
     * 
     * @param authenticationToken The {@link AuthenticationToken} to check access for.
     * @param resources String identifier(s) of the resource(s) in question.
     * @return True if user is authorized, false if not. 
     */
    boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String... resources);
    
    /**
     * Checks if the current user is authorized for the given resource.
     * Will not create any audit log. 
     * 
     * @param authenticationToken The {@link AuthenticationToken} to check access for.
     * @param requireRecursive true if only accept recursive values should be accepted. 
     * @param resources String identifier(s) of the resource(s) in question.
     * @return True if user is authorized, false if not. 
     */
    boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, boolean requireRecursive, String... resources);

    /**
     * Helper method to clear the local access control rule cache. Normally the cache expires after configured time, but when modifying access rules
     * on the local node we can force cache clearing so we don't have to wait. Other nodes in a cluster will still wait until expire though. This
     * should be called whenever "accessTreeUpdateSession.signalForAccessTreeUpdate()" is called, it can't be called automatically from that method
     * due to circular dependencies.
     */
    void forceCacheExpire();

    /**
     * Returns all rules that the given authenticationToken is allowed to access. Includes *SOME wildcard rules
     * @throws AuthenticationFailedException On authentication errors, such as an invalid password for a CLI token
     */
    AccessSet getAccessSetForAuthToken(AuthenticationToken authenticationToken) throws AuthenticationFailedException;
    


}
