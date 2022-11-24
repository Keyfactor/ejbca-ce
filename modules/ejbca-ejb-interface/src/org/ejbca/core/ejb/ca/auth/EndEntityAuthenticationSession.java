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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Provides access to authentication system.
 */
public interface EndEntityAuthenticationSession {

    /**
     * Authenticates a user to the user database and returns the user DN.
     *
     * @param username unique username within the instance
     * @param password password for the user
     * @return EndEntityInformation, never returns null
     * @throws NoSuchEndEntityException if the user does not exist.
     * @throws AuthStatusException      if the end entity's status is not one of NEW, FAILED, IN_PROCESS or KEY_RECOVERY
     * @throws AuthLoginException       If the password is incorrect.
     */
    EndEntityInformation authenticateUser(AuthenticationToken admin, String username, String password)
            throws NoSuchEndEntityException, AuthStatusException, AuthLoginException;

    /**
     * Verifies a password for a user, decreasing the remaining login attempts if verification fails and if caller wants (and it is not set to unlimited).
     *
     * @param admin                              the administrator performing the action
     * @param username                           the unique username.
     * @param password                           the password to be verified.
     * @param decRemainingLoginAttemptsOnFailure if true and password verification fails, will try to decrease remaining login attempts (which can be unlimited)
     * @return true if password was correct, false otherwise
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    boolean verifyPassword(AuthenticationToken admin, String username, String password, boolean decRemainingLoginAttemptsOnFailure)
            throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException;

    /**
     * Returns true if the given end entity is allowed to enroll.
     * End entities with status NEW and KEYRECOVERY are allowed, as well as end entities with status
     * GENERATED that are about to expire if "Allow renewal before expiration" is enabled.
     *
     * @param admin Authentication token
     * @param username Username of end entity to check
     * @return true if allowed to enroll. false if not, or if not authorized to the CA of the end entity.
     */
    boolean isAllowedToEnroll(final AuthenticationToken admin, String username);

    /**
     * Check if user is authorized to access the specified end entity profile.
     *
     * @param admin authenticationToken to be check for authorization
     * @param endEntityProfileId id of end entity profile for which operation authorization needs to be checked.
     * @param accessRule end entity access rile to be checked
     * @return true if user is authorized to the end entity profile
     */
    boolean isAuthorizedToEndEntityProfile(final AuthenticationToken admin, final int endEntityProfileId, final String accessRule);

    /**
     * <p>Check if the authentication token has access to an end entity access rule for the specified end entity profile.
     *
     * <p>If the authentication token does not have access an exception is thrown.
     *
     * @param authenticationToken the authentication token to use for authentication
     * @param endEntityProfileId the ID of the end entity profile
     * @param accessRule an end entity access rule
     * @param caId the ID of the CA (used for logging only)
     * @throws AuthorizationDeniedException if the access control check failed
     */
    void assertAuthorizedToEndEntityProfile(AuthenticationToken authenticationToken, int endEntityProfileId, String accessRule, int caId) throws AuthorizationDeniedException;

    /**
     * Check if a user is authorized to access a specific CA.
     *
     * @param authenticationToken the authentication token for the user
     * @param caId the ID of the CA.
     * @return true if the user is authorized to access the CA.
     */
    boolean authorizedToCA(final AuthenticationToken authenticationToken, final int caId);

    /**
     * <p>Check if user is allows to access the specified CA.
     *
     * <p>If the authentication token does not have access an exception is thrown.
     *
     * @param authenticationToken the authentication token for the user
     * @param caId the ID of the CA.
     * @throws AuthorizationDeniedException if the user is not authorized to access the CA.
     */
    void assertAuthorizedToCA(AuthenticationToken authenticationToken, int caId) throws AuthorizationDeniedException;
}
