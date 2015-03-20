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
package org.ejbca.core.ejb.keyrecovery;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.util.KeyPairWrapper;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * @version $Id$
 */
public interface KeyRecoverySession {

    /**
     * Adds a certificates keyrecovery data to the database.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keypair.
     * @param username of the administrator
     * @param keypair the actual keypair to save.
     *
     * @return false if the certificates keyrecovery data already exists.
     * @throws AuthorizationDeniedException if not authorized to administer keys.
     */
    boolean addKeyRecoveryData(AuthenticationToken admin, Certificate certificate, String username, KeyPairWrapper keypair) throws AuthorizationDeniedException;

    /**
     * Updates keyrecovery data
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keypair.
     * @param markedasrecoverable DOCUMENT ME!
     * @param keypair the actual keypair to save.
     *
     * @return false if certificates keyrecovery data does not exist
     * @throws AuthorizationDeniedException if not authorized to administrate keys.
     *
     */
    boolean changeKeyRecoveryData(AuthenticationToken admin, X509Certificate certificate, boolean markedasrecoverable, KeyPairWrapper keypair) throws AuthorizationDeniedException;

    /**
     * Removes a certificates keyrecovery data from the database.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     * @throws AuthorizationDeniedException if not authorized to administer keys
     */
    void removeKeyRecoveryData(AuthenticationToken admin, Certificate certificate) throws AuthorizationDeniedException;

    /** Removes a all keyrecovery data saved for a user from the database. */
    void removeAllKeyRecoveryData(AuthenticationToken admin, String username);

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates
     * key can be recovered for every user at the time.
     * 
     * @param endentityprofileid the end entity profile id the user belongs to.
     * @return the marked keyrecovery data or null if none can be found.
     * @deprecated since 5.1.0 Use org.ejbca.core.ejb.keyrecovery.KeyRecoverySession.recoverKeys(AuthenticationToken, String, int) instead 
     */
    org.ejbca.core.model.keyrecovery.KeyRecoveryInformation keyRecovery(AuthenticationToken admin, String username, int endEntityProfileId)
            throws AuthorizationDeniedException;

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates
     * key can be recovered for every user at the time.
     * 
     * @param endentityprofileid the end entity profile id the user belongs to.
     * @return the marked keyrecovery data or null if none can be found.
     */
    org.ejbca.core.model.keyrecovery.KeyRecoveryInformation recoverKeys(AuthenticationToken admin, String username, int endEntityProfileId)
            throws AuthorizationDeniedException;

    /**
     * Marks a users newest certificate for key recovery. Newest means certificate with latest not
     * before date.
     *
     * @param admin the administrator calling the function
     * @param username or the user.
     * @param the end entity profile of the user, used for access control
     * @return true if operation went successful or false if no certificates could be found for
     *         user, or user already marked.
     */
    boolean markNewestAsRecoverable(AuthenticationToken admin, String username, int endEntityProfileId)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException;

    /**
     * Marks a users certificate for key recovery.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     * @return true if operation went successful or false if  certificate couldn't be found.
     */
    boolean markAsRecoverable(AuthenticationToken admin, Certificate certificate, int endEntityProfileId)
            throws AuthorizationDeniedException, WaitingForApprovalException, ApprovalException;

    /** Resets keyrecovery mark for a user. */
    void unmarkUser(AuthenticationToken admin, String username);

    /** @return true if user is already marked for key recovery. */
    boolean isUserMarked(String username);

    /**
     * @param certificate the certificate used with the keys about to be removed.
     * @return true if specified certificates keys exists in database.
     */
    boolean existsKeys(Certificate certificate);
}
