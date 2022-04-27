/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.authorization;

import java.util.Map;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * @see AuthorizationSystemSession
 * @version $Id$
 */
@Remote
public interface AuthorizationSystemSessionRemote extends AuthorizationSystemSession {

    /** @return a Map of all authorized <resource,resourceName> on this installation (optionally ignoring if certain resources is not in use) */
    Map<String,String> getAllResources(AuthenticationToken authenticationToken, boolean ignoreLimitations);

}
