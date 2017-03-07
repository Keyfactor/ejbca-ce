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

import java.util.HashMap;

import javax.ejb.Local;
import javax.ejb.Timer;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * 
 * @version $Id$
 */
@Local
public interface AuthorizationSessionLocal extends AuthorizationSession {

    /** Invoked when authorization cache should be checked for updates. */
    void refreshAuthorizationCache();

    /** Invoked by background cache refresh timeouts */
    void timeOut(Timer timer);

    /** Initialize background cache refresh timeouts */
    void scheduleBackgroundRefresh();

    /** @return the access rules available to the AuthenticationToken and its nested tokens, taking each such tokens role membership into account */
    HashMap<String, Boolean> getAccessAvailableToAuthenticationToken(AuthenticationToken authenticationToken) throws AuthenticationFailedException;
}
