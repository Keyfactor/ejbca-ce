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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.keys.util.KeyPairWrapper;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;

/**
 * @version $Id$
 */
public interface KeyRecoverySession {

     /**
     * Method checking the following authorizations:
     * 
     * If /superadmin -> true
     * 
     * Other must have both
     * AccessRulesConstants.
     *  /ra_functionality/keyrecovery
     *  and /endentityprofilesrules/<endentityprofile>/keyrecovery
     * 
     * @param admin authentication token of requesting administrator
     * @param profileid end entity profile
     * @return true if the admin is authorized to keyrecover
     */
    public boolean authorizedToKeyRecover(AuthenticationToken admin, int profileid);
    
    /**
     * Help method to check if approval of key recovery is required
     * @param admin authentication token of requesting administrator
     * @param certificate to recover
     * @param username of the end entity related to the certificate
     * @param endEntityProfileId used by the end entity
     * @param checkNewest 
     * @throws ApprovalException if approval already exists
     * @throws WaitingForApprovalException if approval is required. Expected to be thrown in this case. The request ID will be included as a field in this exception.
     * @throws CADoesntExistsException if the issuer of the certificate doesn't exist
     */
    public void checkIfApprovalRequired(AuthenticationToken admin, CertificateWrapper certificate, String username, int endEntityProfileId, boolean checkNewest) 
            throws ApprovalException, WaitingForApprovalException, CADoesntExistsException;
    
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
    boolean addKeyRecoveryData(AuthenticationToken admin, CertificateWrapper certificate, String username, KeyPairWrapper keypair) throws AuthorizationDeniedException;

    /**
     * Removes a certificates keyrecovery data from the database.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     * @throws AuthorizationDeniedException if not authorized to administer keys
     */
    void removeKeyRecoveryData(AuthenticationToken admin, CertificateWrapper certificate) throws AuthorizationDeniedException;

    /** Removes a all keyrecovery data saved for a user from the database. If no key recovery data exists, nothing is done. 
     * 
     * @param admin the administrator calling the function
     * @param username the end entity for which to remove all key recovery data entries
     */
    void removeAllKeyRecoveryData(AuthenticationToken admin, String username);

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates
     * key can be recovered for every user at the time.
     * 
     * @param endentityprofileid the end entity profile id the user belongs to.
     * @return the marked keyrecovery data or null if none can be found.
     * 
     * @throws AuthorizationDeniedException if not authorized to recover keys
     */
     KeyRecoveryInformation recoverKeys(AuthenticationToken admin, String username, int endEntityProfileId)
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
     *         
     * @throws CADoesntExistsException if the issuer of the certificate doesn't exist
     */
    boolean markNewestAsRecoverable(AuthenticationToken admin, String username, int endEntityProfileId)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, CADoesntExistsException;

    /**
     * Marks a users certificate for key recovery.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     * @return true if operation went successful or false if  certificate couldn't be found.
     * 
     * @throws CADoesntExistsException if the issuer of the certificate doesn't exist
     */
    boolean markAsRecoverable(AuthenticationToken admin, Certificate certificate, int endEntityProfileId)
            throws AuthorizationDeniedException, WaitingForApprovalException, ApprovalException, CADoesntExistsException;
    
    /** Resets keyrecovery mark for a user. */
    void unmarkUser(AuthenticationToken admin, String username);

    /** @return true if user is already marked for key recovery. */
    boolean isUserMarked(String username);

    /**
     * @param certificate the certificate used with the keys about to be removed.
     * @return true if specified certificates keys exists in database.
     */
    boolean existsKeys(CertificateWrapper certificate);
}
