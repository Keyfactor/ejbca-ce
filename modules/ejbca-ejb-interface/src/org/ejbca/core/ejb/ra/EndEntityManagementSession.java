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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/** Session bean handling end entity administration, i.e. adding and editing end entities. 
 * 
 * @version $Id$
 */
public interface EndEntityManagementSession {

    /**
     * Check if user is authorized for specified an EE access rule for specified EEP.
     * @param admin authenticationToken to be check for authorization
     * @param profileid id of EEP for which operation authorization needs to be checked
     * @param rights EE access rule to be checked (etc. AccessRulesConstants.DELETE_END_ENTITY...)
     * @return true if user is authorized for specified EE access rules for specified EEP, false otherwise
     */
    boolean isAuthorizedToEndEntityProfile(final AuthenticationToken admin, final int profileid, final String rights);
    
    
    /**
     * Important: this method is old and shouldn't be used, use
     * addUser(..EndEntityInformation...) instead.
     * 
     * @param admin the administrator performing the action
     * @param username the unique user name.
     * @param password the password used for authentication.
     * @param subjectdn the DN the subject is given in his certificate.
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject or null.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @param endentityprofileid
     *            the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile
     *            that should be generated for the user.
     * @param type of user i.e administrator, keyrecoverable and/or
     *            sendnotification, from SecConst.USER_XX.
     * @param tokentype the type of token to be generated, one of
     *            SecConst.TOKEN constants
     * @param hardwaretokenissuerid if token should be hard, the id of the hard
     *            token issuer, else 0.
     * @param caid the CA the user should be issued from.
     * @throws CADoesntExistsException if the caid of the user does not exist
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws ApprovalException if an approval already exists for this request.
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws EndEntityExistsException if an end entity by the specified username already exists
     */
    void addUser(AuthenticationToken admin, String username, String password, String subjectdn, String subjectaltname, String email,
    		boolean clearpwd, int endentityprofileid, int certificateprofileid, EndEntityType type, int tokentype, int hardwaretokenissuerid, int caid)
    		throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
    		CADoesntExistsException, EndEntityExistsException, CustomFieldException, IllegalNameException, ApprovalException, CertificateSerialNumberException;

    /**
     * addUserFromWS is called from EjbcaWS if profile specifies merge data from
     * profile to user we merge them before calling addUser
     * 
     * @param admin the administrator pwrforming the action
     * @param userdata a EndEntityInformation object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fulfill requirements of end entity profile
     * @throws EndEntityExistsException
     *             if user already exists or some other database error occur during commit
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws ApprovalException if an approval already exists for this request.
     * @throws IllegalNameException if the Subject DN failed constraints
     */
    void addUserFromWS(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, CustomFieldException, IllegalNameException, ApprovalException, CertificateSerialNumberException;

    /**
     * Add a new user.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, the fields status, timecreated and timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the db, otherwise it is hashed.
     * @return returned object contains the same sensitive information as was passed in clearpwd, or an autogenerated pwd.
     * @throws AuthorizationDeniedException if the administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException if data doesn't fulfill requirements of the end entity profile
     * @throws EndEntityExistsException if user already exists or some other database error occurs during commit
     * @throws WaitingForApprovalException if approval is required and the action has been added in the approval queue.
     * @throws IllegalNameException if the Subject DN or SAN failed constraints
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws ApprovalException if an approval already exists for this request.
     * @throws CertificateSerialNumberException if the CA requires that Subject DN Serial Numbers be unique, and the one specified here already exists.
     */
    EndEntityInformation addUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, IllegalNameException, CustomFieldException, ApprovalException, CertificateSerialNumberException;

    /**
     * Add a new user after an AddEndEntityApprovalRequest had been approved.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @param approvalRequestID the unique ID of the approval request (not the hash)
     * @param lastApprovingAdmin The last administrator to have approved the request
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fulfill requirements of end entity profile
     * @throws EndEntityExistsException
     *             if user already exists or some other database error occur during commit
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws WaitingForApprovalException
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws ApprovalException if an approval already exists for this request.
     * @throws CertificateSerialNumberException  if SubjectDN serial number already exists.
     */
    void addUserAfterApproval(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, CustomFieldException, IllegalNameException, ApprovalException, CertificateSerialNumberException;
        
    /**
     * Change user information.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timecreated and timemodified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fullfil requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;

    /**
     * Change user information.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timeCreated and timeModified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @param fromWebService The service is called from webService
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fllfil requirements of end entity profile
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws ApprovalException if an approval already exists for this request.
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, boolean fromWebService)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;

    /**
     * Change user information.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timecreated and timemodified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @param newUsername the new username of the end entity
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fullfil requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws NoSuchEndEntityException if the end entity was not found
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, String newUsername)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;
    
    /**
     * Change user information after an EditEndEntityApprovalRequest has been approved
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timecreated and timemodified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @param approvalRequestId the unique ID of the approval request (not the hash)
     * @param lastApprovingAdmin the last administrator to have approved the request
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fulfill requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws NoSuchEndEntityException NoSuchEndEntityException if the user does not exist
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUserAfterApproval(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, 
            int approvalRequestId, AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;
    
    /**
     * Change user information after an EditEndEntityApprovalRequest has been approved
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, timecreated and timemodified will
     *             not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *             db, otherwise it is hashed.
     * @param approvalRequestId the unique ID of the approval request (not the hash)
     * @param lastApprovingAdmin the last administrator to have approved the request
     * @param oldUsername the username the end entity has prior to the name change
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException
     *             if data doesn't fulfill requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws NoSuchEndEntityException NoSuchEndEntityException if the user does not exist
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    void changeUserAfterApproval(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, 
            int approvalRequestId, AuthenticationToken lastApprovingAdmin, String oldUsername)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;
    
    /**
     * Deletes a user from the database. The users certificates must be revoked
     * BEFORE this method is called.
     * 
     * @param username the unique username.
     * @throws AuthorizationDeniedException if admin was not authorized to remove end entities
     * @throws NoSuchEndEntityException if the user does not exist.
     * @throws CouldNotRemoveEndEntityException if the user could not be deleted.
     */
    void deleteUser(AuthenticationToken admin, String username) throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException;

    /**
     * Changes status of a user.
     * 
     * @param admin An authentication token 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * 
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
     */
    void setUserStatus(AuthenticationToken admin, String username, int status) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException;

    /**
     * Changes status of a user. This method is called mainly when executing a ChangeStatusEndEntityApprovalRequest
     * 
     * @param admin An authentication token 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @param approvalRequestId The ID of the approval request submitted to change the status
     * @param lastApprovingAdmin the last administrator to have approved the request
     * 
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
     * @throws NoSuchEndEntityException if the end entity was not found
     * 
     */
    void setUserStatusAfterApproval(AuthenticationToken admin, String username, int status, int approvalRequestID,
            AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, NoSuchEndEntityException;
    
    /**
     * Sets a new password for a user.
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the new password for the user, NOT null.
     * 
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    void setPassword(AuthenticationToken admin, String username, String password) throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException;

    /**
     * Sets a clear text password for a user.
     * 
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting
     *            password to 'null' effectively deletes any previous clear
     *            text password.
     * 
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    void setClearTextPassword(AuthenticationToken admin, String username, String password) throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException;

    /**
     * Verifies a password for a user, decreasing the remaining login attempts if verification fails and if caller wants (and it is not set to unlimited).
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the password to be verified.
     * @param decRemainingLoginAttemptsOnFailure if true and password verification fails, will try to decrease remaining login attempts (which can be unlimited)
     * @return true if password was correct, false otherwise
     * 
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    boolean verifyPassword(AuthenticationToken admin, String username, String password, boolean decRemainingLoginAttemptsOnFailure)
            throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException;
    
    /** 
     * Revoke and then delete a user. 
     * @throws ApprovalException if an approval already exists for this request.
     * @throws NoSuchEndEntityException if the end entity was not found.
     * @throws CouldNotRemoveEndEntityException if the user could not be deleted.
     */
    void revokeAndDeleteUser(AuthenticationToken admin, String username, int reason)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException;
    
    /**
     * Method that revokes a user. Revokes all users certificates and then sets user status to revoked.
     * If user status is already revoked it still revokes all users certificates, ignoring the ones that are already revoked.
     * 
     * @param username the username to revoke.
     * @param reason revocation reason to use in certificate revocations
     * @throws AlreadyRevokedException if user is revoked and unrevocation is attempted by sending revocation reason NOTREVOKED or REMOVEFROMCRL
     * @throws ApprovalException if revocation has been requested and is waiting for approval.
     * 
     */
    void revokeUser(AuthenticationToken admin, String username, int reason)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

    /**
     * Revokes all of a user's certificates.
     *
     * It is also possible to delete a user after all certificates have been revoked.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/revoke_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/revoke_end_entity
     * - /ca/<ca of users certificate>
     * </pre>
     *
     * @param authenticationToken of the requesting administrator or client.
     * @param username unique username in EJBCA
     * @param reason for revocation, one of {@link org.cesecore.certificates.crl.RevokedCertInfo}.REVOKATION_REASON_ constants or use {@link org.cesecore.certificates.crl.RevokedCertInfo}.NOT_REVOKED to un-revoke a certificate on hold.
     * @param deleteUser deletes the users after all the certificates have been revoked.
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @throws ApprovalException if there already exists an approval request for this task.
     * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved.
     * @throws AlreadyRevokedException if the user already was revoked.
     * @throws NoSuchEndEntityException if End Entity bound to certificate isn't found.
     * @throws CouldNotRemoveEndEntityException if the user could not be deleted.
     * @throws EjbcaException any EjbcaException.
     */
    void revokeUser(AuthenticationToken authenticationToken, String username, int reason, boolean deleteUser) throws AuthorizationDeniedException, 
        CADoesntExistsException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException, NoSuchEndEntityException, 
        CouldNotRemoveEndEntityException, EjbcaException;
    
    /**
     * Method that revokes a user. Revokes all users certificates and then sets user status to revoked.
     * If user status is already revoked it still revokes all users certificates, ignoring the ones that are already revoked.
     * This method is called mainly when executing a RevocationApprovalRequest
     * 
     * @param username the username to revoke.
     * @param reason revocation reason to use in certificate revocations
     * @param approvalRequestId the ID of the approval request submitted to revoke the user
     * @param lastApprovingAdmin the last administrator to have approved the request
     * @throws AlreadyRevokedException if user is revoked and unrevocation is attempted by sending revocation reason NOTREVOKED or REMOVEFROMCRL
     * @throws ApprovalException if revocation has been requested and is waiting for approval.
     * 
     */
    void revokeUserAfterApproval(AuthenticationToken admin, String username, int reason, int approvalRequestID, AuthenticationToken lastApprovingAdmin) 
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

    /**
     * Same as {@link #revokeCert(AuthenticationToken, BigInteger, String, int)} but also sets the revocation date.
     * 
     * @param admin
     * @param certserno
     * @param revocationdate after this the the certificate is not valid
     * @param issuerdn
     * @param reason
     * @param checkPermission if true and if 'revocationdate' is not null then the certificate profile must allow back dating otherwise a {@link RevokeBackDateNotAllowedForProfileException} is thrown.
     * 
     * @throws AuthorizationDeniedException
     * @throws NoSuchEndEntityException if certificate to revoke can not be found
     * @throws ApprovalException if revocation has been requested and is waiting for approval.
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     * @throws RevokeBackDateNotAllowedForProfileException
     */
    void revokeCert(AuthenticationToken admin, BigInteger certserno, Date revocationdate, String issuerdn, int reason, boolean checkPermission)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException,
            RevokeBackDateNotAllowedForProfileException;

    /**
     * Method that revokes a certificate for a user. It can also be used to
     * un-revoke a certificate that has been revoked with reason ON_HOLD. This
     * is done by giving reason RevokedCertInfo.NOT_REVOKED (or
     * RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL).
     * 
     * @param admin the administrator performing the action
     * @param certserno the serno of certificate to revoke.
     * @param issuerdn
     * @param reason the reason of revocation, one of the RevokedCertInfo.XX
     *            constants. Use RevokedCertInfo.NOT_REVOKED to re-activate a
     *            certificate on hold.
     * @throws AlreadyRevokedException if the certificate was already revoked
     * @throws NoSuchEndEntityException if certificate to revoke can not be found
     * @throws ApprovalException if an approval already exists for this request.
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     */
    void revokeCert(AuthenticationToken admin, BigInteger certserno, String issuerdn, int reason)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;
    
    
    /**
     * Method that revokes a certificate for a user. It can also be used to
     * un-revoke a certificate that has been revoked with reason ON_HOLD. This
     * is done by giving reason RevokedCertInfo.NOT_REVOKED (or
     * RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL).
     * 
     * reason, certificateProfileId and revocationdate can be included as 
     * input parameters wrapped into CertRevocationDto dto class.
     * 
     * @param admin token of the administrator performing the action
     * @param certRevocationDto wrapper object of the input parameters for the revoke.
     * 
     * @throws AlreadyRevokedException if the certificate was already revoked
     * @throws NoSuchEndEntityException if certificate to revoke can not be found
     * @throws ApprovalException if an approval already exists for this request.
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     * @throws CertificateProfileDoesNotExistException if no profile was found with certRevocationDto.certificateProfileId input parameter.
     */
    void revokeCertWithMetadata(AuthenticationToken admin, CertRevocationDto certRevocationDto)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException,
            RevokeBackDateNotAllowedForProfileException, CertificateProfileDoesNotExistException;
    
    /**
     * Method that revokes a certificate for a user. It can also be used to
     * un-revoke a certificate that has been revoked with reason ON_HOLD. This
     * is done by giving reason RevokedCertInfo.NOT_REVOKED (or
     * RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL).
     * 
     * This method is called mainly when executing a RevocationApprovalRequest
     * 
     * @param admin the administrator performing the action
     * @param certserno the serno of certificate to revoke.
     * @param issuerdn
     * @param reason the reason of revocation, one of the RevokedCertInfo.XX
     *            constants. Use RevokedCertInfo.NOT_REVOKED to re-activate a
     *            certificate on hold.
     * @param approvalRequestId the ID of the approval request submitted to revoke the certificate
     * @param lastApprovingAdmin the last administrator to have approved the request
     * @throws AlreadyRevokedException if the certificate was already revoked
     * @throws NoSuchEndEntityException
     * @throws ApprovalException if an approval already exists for this request.
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     */
    void revokeCertAfterApproval(AuthenticationToken admin, BigInteger certserno, String issuerdn, int reason, int approvalRequestID,
            AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;
    
    /**
     * Method that checks if a user with specified users certificate exists in
     * database. IssuerDN/serialNumber is the unique key for a certificate.
     *
     * @param certificatesnr serial number of certificate
     * @param issuerdn issuerDN of certificate
     * @return true if certificate belongs to a user, false if no user with specified certificate exists
     */
    boolean checkIfCertificateBelongToUser(BigInteger certificatesnr, String issuerdn);
    
    /**
     * Method checking if username already exists in database. WARNING: do not
     * use this method where an authorization check is needed, use findUser
     * there instead.
     * 
     * @return true if username already exists.
     */
    boolean existsUser(String username);

    /**
     * Mark a user's certificate for key recovery and set the user status to
     * EndEntityConstants.STATUS_KEYRECOVERY.
     * 
     * @param admin used to authorize this action
     * @param username is the user to key recover a certificate for
     * @param certificate is the certificate to recover the keys for. Use
     *            'null' to recovery the certificate with latest not before
     *            date.
     * @return true if the operation was successful
     * 
     * @throws if an approval already exists for this request.
     */
    boolean prepareForKeyRecovery(AuthenticationToken admin, String username, int endEntityProfileId, Certificate certificate)
    		throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, CADoesntExistsException;
    
    /**
     * Marks a user for key recovery and performs authorization checks. This method will not mark the certificate for key recover.  
     * Method is intended to be used when KeyRecoveryData is not present in the instance database (eg. when local key generation is enabled). 
     * 
     * @param admin used to authorize this action
     * @param username is the user to key recover a certificate for
     * @param endEntityProfileId of the end entity related to certificate
     * @param certificate used to check if approval is required to recover this certificate
     * @return true if operation was completed successfully
     * @throws AuthorizationDeniedException if requesting administrator isn't authorized to perform key recovery
     * @throws ApprovalException if an approval already exists to edit user status
     * @throws CADoesntExistsException if CA holding the user does not exist
     * @throws WaitingForApprovalException if the request requires approval. Expected to be thorws if approval is required to edit end entity
     */
    public boolean prepareForKeyRecoveryInternal(AuthenticationToken admin, String username, int endEntityProfileId, Certificate certificate) 
            throws AuthorizationDeniedException, ApprovalException, CADoesntExistsException, WaitingForApprovalException;
    
    /**
     * Selects a list of specific list of EndEntityInformation entities, as filtered by
     * the below parameters. 
     * 
     * @param caIds The list of CAIDs to filter by. If this list is empty, all
     *            the UserData objects that match the given expiration and
     *            status are returned.
     * @param timeModified Not modified since this date, as expressed by a Long
     *            value 
     * @param status Status of the requested CAIDs
     * @return
     */
    List<EndEntityInformation> findUsers(List<Integer> caIds, long timeModified, int status);

    /**
     * Rename an end entity.
     * Updates existing references in the database to this username.
     * 
     * No re-publishing with updated username will take place.
     * 
     * @param admin administrator that 
     * @param currentUsername
     * @param newUsername
     * @return true if an end entity with such name existed
     * @throws AuthorizationDeniedException if the user was not authorized to edit this end entity
     * @throws EndEntityExistsException the newUsername is already taken by another end entity
     */
    boolean renameEndEntity(AuthenticationToken admin, String currentUsername, String newUsername) throws AuthorizationDeniedException, EndEntityExistsException;
}
