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

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;

/**
 * Interface for high level authorization system tasks.
 *
 * @version $Id$
 */
public interface AuthorizationSystemSession {

    public static final String SUPERADMIN_ROLE = "Super Administrator Role";

    /**
     * Returns all rules that the given authenticationToken is allowed to access. Includes *SOME wildcard rules
     * @throws AuthenticationFailedException On authentication errors, such as an invalid password for a CLI token
     */
    AccessSet getAccessSetForAuthToken(AuthenticationToken authenticationToken) throws AuthenticationFailedException;
    
    /** Configure the provided CN as a RoleMember of the Super Administrator Role if the caller has sufficient privileges. */
    boolean initializeAuthorizationModuleWithSuperAdmin(AuthenticationToken authenticationToken, int caId, String superAdminCN)
            throws AuthorizationDeniedException;
}
