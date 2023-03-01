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
package org.ejbca.core.ejb.ra;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Local interface for EndEntityManagementSession.
 */
@Local
public interface EndEntityManagementSessionLocal extends EndEntityManagementSession {

    /**
     * Validates the name and DN in an end entity and canonicalizes/strips
     * the attributes. This method is called by addUser.
     * 
     * @return a copy of endEntity with the canonicalized changes. Does not modify its parameter.
     * 
     * @throws CustomFieldException if if the end entity was not validated by a locally defined field validator
     * 
     */
    EndEntityInformation canonicalizeUser(final EndEntityInformation endEntity) throws CustomFieldException;
    

    /**
     * Methods that checks if a user exists in the database having the given
     * caid. This function is mainly for avoiding desynchronization when a CAs
     * is deleted.
     * 
     * @param caid the id of CA to look for.
     * @return true if caid exists in UserData table.
     */
    boolean checkForCAId(int caid);
    
    /**
     * Removes the certificate serial number from the user data.
     * @param userName the unique username.
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    void cleanUserCertDataSN(String userName) throws NoSuchEndEntityException;
    
    /**
     * Cleans the certificate serial number and certificate request (CSR) from database userData table.
     * @param userName the unique username.
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    void cleanSerialnumberAndCsrFromUserData(String userName) throws NoSuchEndEntityException;

    
    /**
     * Decreases (the optional) request counter by 1, until it reaches 0.
     * Returns the new value. If the value is already 0, -1 is returned, but the
     * -1 is not stored in the database. Also sets status of user to generated
     * once the request counter reaches zero.
     * 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @throws NoSuchEndEntityException if user does not exist
     */
    int decRequestCounter(String username) throws NoSuchEndEntityException, ApprovalException, WaitingForApprovalException;
        
    /**
     * Changes the CAId of the given end-entity. Intended to be used when an uninitialized CA's subject DN and CAId is changed
     * (CAs can be in the uninitialized state when they have been imported from a statedump).
     * 
     * @param admin Authentication token
     * @param username End-entity to change CAId of
     * @param newCAId CA id to change to.
     */
    void updateCAId(final AuthenticationToken admin, final String username, int newCAId) throws AuthorizationDeniedException, NoSuchEndEntityException;
    
    /**
     * Change user information, ignoring approval requirements. 
     * 
     * <b>Warning:</b> This method should only be used internally when the system needs to modify the information about an end entity in a way that bypasses 
     * approval requirements. Do not use this method unless that is the understood intention. 
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timecreated and timemodified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @param force 
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fullfil requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue. The request ID will be included as a field in this exception.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUserIgnoreApproval(AuthenticationToken admin, EndEntityInformation endEntityInformation, boolean clearpwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;

    /**
     * Used to set user status and log audit event where userdata is 
     * updated also outside the function in same transaction.
     * 
     * @param authenticationToken
     * @param data1
     * @param status
     * @param approvalRequestID
     * @param lastApprovingAdmin
     * @throws ApprovalException
     * @throws WaitingForApprovalException
     */
    void setUserStatus(AuthenticationToken authenticationToken, UserData data1, int status, int approvalRequestID,
            AuthenticationToken lastApprovingAdmin) throws ApprovalException, WaitingForApprovalException;

    /**
     * Saves a per-transaction shadow copy of the end entity (in memory, not in database).
     * This way, unnecessary modifications can be suppressed, and harmless transaction conflicts can be ignored.
     * <p>
     * This is only meaningful for add/edit operations of end entities (including setUserStatus, finishUser, etc.)
     *
     * @param username End entity username
     * @return A copy of the existing end entity, or null.
     */
    EndEntityInformation initializeEndEntityTransaction(String username);

    /**
     * Suppresses "unwanted" changes to the UserData from the current transaction, and. <strong>The UserData object
     * will be detached from the EntityManager in that case.</strong>
     * <p>
     * This requires that {@link #initializeEndEntityTransaction(String)} has been called before.
     * <p>
     * A change is considered unwanted in the following cases:
     * <ol>
     * <li>"Update UserData on issuance" is disabled in the certificate profile.
     * <li>In case the new status is GENERATED, there are no changes besides the modification time and password.
     * <li>For other statuses, there are no changes besides the modification time.
     * </ol>
     *
     * @param username  Username of user
     * @see #initializeEndEntityTransaction
     */
    void suppressUnwantedUserDataChanges(String username);

    /**
     * Used internally to migrate certain updates of UserData during certificate to a separate transaction.
     * @see #initializeEndEntityTransaction
     */
    void changeUserInNewTransaction(UserData newUserData, boolean isNew);

}
