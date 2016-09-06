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
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

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
     */
    void addUser(AuthenticationToken admin, String username, String password, String subjectdn, String subjectaltname, String email,
    		boolean clearpwd, int endentityprofileid, int certificateprofileid, EndEntityType type, int tokentype, int hardwaretokenissuerid, int caid)
    		throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
    		CADoesntExistsException, EndEntityExistsException, EjbcaException;

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
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws EndEntityExistsException
     *             if user already exists or some other database error occur during commit
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     */
    void addUserFromWS(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            EndEntityExistsException, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Add a new user.
     * 
     * @param admin the administrator performing the action
     * @param userdata a EndEntityInformation object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws EndEntityExistsException
     *             if user already exists or some other database error occur during commit
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     * @throws WaitingForApprovalException
     */
    void addUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            EndEntityExistsException, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Validates the name and DN in an end entity and canonicalizes/strips
     * the attributes. This method is called by addUser.
     */
     void canonicalizeUser(final EndEntityInformation endEntity) throws EjbcaException;
    
    /**
     * Changes data for a user in the database specified by username.
     * 
     * Important, this method is old and shouldn't be used, user
     * changeUser(..EndEntityInformation...) instead.
     * 
     * @param username the unique username.
     * @param password the password used for authentication.*
     * @param subjectdn the DN the subject is given in his certificate.
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject or null.
     * @param endentityprofileid the id number of the end entity profile bound
     *             to this user.
     * @param certificateprofileid the id number of the certificate profile
     *             that should be generated for the user.
     * @param type of user i.e administrator, keyrecoverable and/or
     *             sendnotification
     * @param tokentype the type of token to be generated, one of
     *             SecConst.TOKEN constants
     * @param hardwaretokenissuerid if token should be hard, the id of the hard
     *             token issuer, else 0.
     * @param status the status of the user, from EndEntityConstants.STATUS_X
     * @param caid the id of the CA that should be used to issue the users
     *             certificate
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     * 
     * @deprecated use {@link #changeUser(AuthenticationToken, EndEntityInformation, boolean)} instead
     */
    @Deprecated
    void changeUser(AuthenticationToken admin, String username, String password, String subjectdn, String subjectaltname, String email, boolean clearpwd,
    		int endentityprofileid, int certificateprofileid, EndEntityType type, int tokentype, int hardwaretokenissuerid, int status, int caid) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

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
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     */
    void changeUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, CADoesntExistsException, EjbcaException;

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
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException if the caid of the user does not exist
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     * @throws javax.ejb.EJBException if the user does not exist
     */
    void changeUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, boolean fromWebService)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Deletes a user from the database. The users certificates must be revoked
     * BEFORE this method is called.
     * 
     * @param username the unique username.
     * @throws NotFoundException if the user does not exist
     * @throws RemoveException if the user could not be removed
     */
    void deleteUser(AuthenticationToken admin, String username) throws AuthorizationDeniedException, NotFoundException, RemoveException;

    /**
     * Changes status of a user.
     * 
     * @param admin An authentication token 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @param approvalRequestId The ID of the approval request submitted to change the status (will only be populated if the method was called when executing a ChangeStatusEndEntityApprovalRequest)
     * 
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
     */
    void setUserStatus(AuthenticationToken admin, String username, int status, int approvalRequestId) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException;

    /**
     * Sets a new password for a user.
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the new password for the user, NOT null.
     */
    void setPassword(AuthenticationToken admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /**
     * Sets a clear text password for a user.
     * 
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting
     *            password to 'null' effectively deletes any previous clear
     *            text password.
     */
    void setClearTextPassword(AuthenticationToken admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /**
     * Verifies a password for a user.
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the password to be verified.
     * @return true if password was correct, false otherwise
     */
    boolean verifyPassword(AuthenticationToken admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /**
     * Method to execute a customized query on the ra user data. The parameter
     * query should be a legal Query object.
     * 
     * @param query a number of statements compiled by query class to a SQL
     *            'WHERE'-clause statement.
     * @param caauthorizationstring is a string placed in the where clause of
     *            SQL query indication which CA:s the administrator is
     *            authorized to view.
     * @param endentityprofilestring is a string placed in the where clause of
     *            SQL query indication which endentityprofiles the
     *            administrator is authorized to view.
     * @param numberofrows the number of rows to fetch, use 0 for the maximum query count define in the global configuration.
     * @param endentityAccessRule The end entity access rule that is necessary 
     *            to execute the query
     * @return a collection of EndEntityInformation.
     * @throws IllegalQueryException when query parameters internal rules isn't
     *            fulfilled.
     * @see org.ejbca.util.query.Query
     */
    Collection<EndEntityInformation> query(AuthenticationToken admin, Query query, String caauthorizationstring,
            String endentityprofilestring, int numberofrows, String endentityAccessRule) throws IllegalQueryException;
    
    /** Revoke and then delete a user. */
    void revokeAndDeleteUser(AuthenticationToken admin, String username, int reason) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, RemoveException, NotFoundException;

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
    void revokeUser(AuthenticationToken admin, String username, int reason) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

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
     * @throws FinderException
     * @throws ApprovalException if revocation has been requested and is waiting for approval.
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     * @throws RevokeBackDateNotAllowedForProfileException
     */
    void revokeCert(AuthenticationToken admin, BigInteger certserno, Date revocationdate, String issuerdn, int reason, boolean checkPermission) throws AuthorizationDeniedException,
            FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException;

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
     * @throws FinderException
     * @throws ApprovalException
     * @throws WaitingForApprovalException
     * @throws AlreadyRevokedException
     */
    void revokeCert(AuthenticationToken admin, BigInteger certserno, String issuerdn, int reason) throws AuthorizationDeniedException,
    		FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

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
     * @param certificateprofileid the ID of the Certificate Profile to check against
     * @return a count of the number of end entities
     */
    long countEndEntitiesUsingCertificateProfile(int certificateprofileid);
    
    /**
     * Finds all users with a specified status.
     * 
     * @param status the status to look for, from 'UserData'.
     * @return Collection of EndEntityInformation
     */
    Collection<EndEntityInformation> findAllUsersByStatus(AuthenticationToken admin, int status);

    /**
     * Finds all users registered to a specified CA.
     * 
     * @param caid the caid of the CA, from 'UserData'.
     * @return Collection of EndEntityInformation, or empty collection if the query is
     *         illegal or no users exist
     */
    Collection<EndEntityInformation> findAllUsersByCaId(AuthenticationToken admin, int caid);

    /**
     * Finds all batch users with a specified status. Limited by the maximum query count define in the global configuration.
     * 
     * @param status the status, from 'UserData'.
     * @return all EndEntityInformation objects or an empty list
     */
    List<EndEntityInformation> findAllBatchUsersByStatusWithLimit(int status);

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
     */
    boolean prepareForKeyRecovery(AuthenticationToken admin, String username, int endEntityProfileId, Certificate certificate)
    		throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, CADoesntExistsException;
    
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
