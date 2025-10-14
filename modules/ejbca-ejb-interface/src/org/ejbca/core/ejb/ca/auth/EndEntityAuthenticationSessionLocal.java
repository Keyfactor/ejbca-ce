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
package org.ejbca.core.ejb.ca.auth;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthStatusException;

import jakarta.ejb.Local;

/**
 * Local interface for AuthenticationSession.
 */
@Local
public interface EndEntityAuthenticationSessionLocal extends EndEntityAuthenticationSession {

    /**
     * Checks that a user is allowed to enroll. This works like {@link #authenticateUser(AuthenticationToken, String, String)
     * except that this methods bypasses the password check (e.g. for self-renewal of a client certificate).
     * <p>
     * Note: There's no point in calling both authenticateUser() and this method.
     *
     * @param username username of end entity
     * @return EndEntityInformation, never returns null
     * @throws NoSuchEndEntityException if the user does not exist.
     * @throws AuthStatusException      if the end entity's status is not one of NEW, FAILED, IN_PROCESS or KEY_RECOVERY
     */
    EndEntityInformation checkAllowedToEnroll(AuthenticationToken admin, String username)
            throws AuthStatusException, NoSuchEndEntityException;

}
