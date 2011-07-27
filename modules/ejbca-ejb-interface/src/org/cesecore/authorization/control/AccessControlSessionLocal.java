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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Local interface for AccessControl
 * 
 * @See {@link AccessControlSession}
 * 
 *      Based on cesecore: AccessControlSessionLocal.java 125 2011-01-20 16:48:11Z mikek
 * 
 * @version $Id$
 * 
 */
@Local
public interface AccessControlSessionLocal extends AccessControlSession {
   
     /**
     * Checks authorization without performing secure audit logging.
     * 
     * @param authenticationToken The authentication token to match against.
     * @param resource The resource to check authorization to.
     * @return true if authorized.
     */
    boolean isAuthorizedNoLog(AuthenticationToken authenticationToken, String resource);
}
