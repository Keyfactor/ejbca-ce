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
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * @see AuthorizationSystemSession
 * @version $Id$
 */
@Remote
public interface AuthorizationSystemSessionRemote extends AuthorizationSystemSession {

    /** @return a Map of all authorized <resource,resourceName> on this installation (optionally ignoring if certain resources is not in use) */
    Map<String,String> getAllResources(AuthenticationToken authenticationToken, boolean ignoreLimitations);

    /** Configure the provided CN as a RoleMember of the Super Administrator Role if the caller has sufficient privileges. */
    boolean initializeAuthorizationModuleWithSuperAdmin(AuthenticationToken authenticationToken, int caId, String superAdminCN)
            throws AuthorizationDeniedException;
}
