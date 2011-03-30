/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.List;

import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.persistence.PersistenceException;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.query.IllegalQueryException;

/** Session bean handling end entity administration, i.e. adding and editing end entities. 
 * 
 * @version $Id$
 */
public interface UserAdminSession {

    /**
     * Important: this method is old and shouldn't be used, use
     * addUser(..UserDataVO...) instead.
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
    public void addUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email,
    		boolean clearpwd, int endentityprofileid, int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid, int caid)
    		throws PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
    		CADoesntExistsException, EjbcaException;

    /**
     * addUserFromWS is called from EjbcaWS if profile specifies merge data from
     * profile to user we merge them before calling addUser
     * 
     * @param admin the administrator pwrforming the action
     * @param userdata a UserDataVO object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws PersistenceException
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
    public void addUserFromWS(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            PersistenceException, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Add a new user.
     * 
     * @param admin the administrator performing the action
     * @param userdata a UserDataVO object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd true if the password will be stored in clear form in the
     *            db, otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws PersistenceException
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
    public void addUser(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            PersistenceException, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Changes data for a user in the database specified by username.
     * 
     * Important, this method is old and shouldn't be used, user
     * changeUser(..UserDataVO...) instead.
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
     * @param status the status of the user, from UserDataConstants.STATUS_X
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
     * @deprecated use {@link #changeUser(Admin, UserDataVO, boolean)} instead
     */
    @Deprecated
    public void changeUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email, boolean clearpwd,
    		int endentityprofileid, int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid, int status, int caid) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Change user information.
     * 
     * @param admin the administrator performing the action
     * @param userdata a UserDataVO object, timecreated and timemodified will
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
    public void changeUser(Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, boolean clearpwd)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, CADoesntExistsException, EjbcaException;

    /**
     * Change user information.
     * 
     * @param admin the administrator performing the action
     * @param userdata a UserDataVO object, timeCreated and timeModified will
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
    public void changeUser(Admin admin, UserDataVO userdata, boolean clearpwd, boolean fromWebService)
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
    public void deleteUser(Admin admin, String username) throws AuthorizationDeniedException, NotFoundException, RemoveException;

    /**
	 * Resets the remaining failed login attempts counter to the user's max login attempts value.
	 * This method does nothing if the counter value is set to UNLIMITED (-1 or not set at all).
     * 
     * @param admin the administrator performing the action
     * @param username the unique username of the user
     * @throws AuthorizationDeniedException if administrator isn't authorized to edit user
     * @throws FinderException if the entity does not exist
     */
    public void resetRemainingLoginAttempts(Admin admin, UserData userData) throws AuthorizationDeniedException, FinderException;

    /**
     * Decrements the remaining failed login attempts counter. If the counter
     * already was zero the status for the user is set to
     * {@link UserDataConstants#STATUS_GENERATED} if it wasn't that already.
     * This method does nothing if the counter value is set to UNLIMITED (-1).
     * 
     * @param admin the administrator performing the action
     * @param username the unique username of the user
     * @throws AuthorizationDeniedException if administrator isn't authorized
     *            to edit user
     * @throws FinderException if the entity does not exist
     */
    public void decRemainingLoginAttempts(Admin admin, String username) throws AuthorizationDeniedException, FinderException;

    /**
     * Decreases (the optional) request counter by 1, until it reaches 0.
     * Returns the new value. If the value is already 0, -1 is returned, but the
     * -1 is not stored in the database. Also sets status of user to generated
     * once the request counter reaches zero.
     * 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @throws FinderException if user does not exist
     */
    public int decRequestCounter(Admin admin, String username) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException;

    /**
     * Cleans the certificate serial number from the user data. Should be called
     * after the data has been used.
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     */
    public void cleanUserCertDataSN(UserDataVO data) throws ObjectNotFoundException;

    /**
     * Removes the certificate serial number from the user data.
     * @param username the unique username.
     */
    public void cleanUserCertDataSN(Admin admin, String username) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException;

    /**
     * Changes status of a user.
     * 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if approval is required and the
     *             action have been added in the approval queue.
     */
    public void setUserStatus(Admin admin, String username, int status) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException;

    /**
     * Sets a new password for a user.
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the new password for the user, NOT null.
     */
    public void setPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /**
     * Sets a clear text password for a user.
     * 
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting
     *            password to 'null' effectively deletes any previous clear
     *            text password.
     */
    public void setClearTextPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /**
     * Verifies a password for a user.
     * 
     * @param admin the administrator performing the action
     * @param username the unique username.
     * @param password the password to be verified.
     */
    public boolean verifyPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException;

    /** Revoke and then delete a user. */
    public void revokeAndDeleteUser(Admin admin, String username, int reason) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, RemoveException, NotFoundException;

    /**
     * Method that revokes a user.
     * @param username the username to revoke.
     * @throws AlreadyRevokedException if the certificate was already revoked
     */
    public void revokeUser(Admin admin, String username, int reason) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

    /**
     * Method that revokes a certificate for a user. It can also be used to
     * un-revoke a certificate that has been revoked with reason ON_HOLD. This
     * is done by giving reason RevokedCertInfo.NOT_REVOKED (or
     * RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL).
     * 
     * @param admin the administrator performing the action
     * @param certserno the serno of certificate to revoke.
     * @param reason the reason of revocation, one of the RevokedCertInfo.XX
     *            constants. Use RevokedCertInfo.NOT_REVOKED to re-activate a
     *            certificate on hold.
     * @throws AlreadyRevokedException if the certificate was already revoked
     */
    public void revokeCert(Admin admin, BigInteger certserno, String issuerdn, int reason) throws AuthorizationDeniedException,
    		FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException;

    /**
     * Method that looks up the username and email address for a administrator
     * and returns the populated Admin object.
     * 
     * @param certificate is the administrators certificate
     */
    public Admin getAdmin(Certificate certificate);

    /**
     * Finds a user by username.
     * 
     * @param admin the administrator performing the action
     * @return UserDataVO or null if the user is not found.
     */
    public UserDataVO findUser(Admin admin, String username) throws AuthorizationDeniedException;

    /**
     * Finds a user by its subject and issuer DN.
     * @return UserDataVO or null if the user is not found.
     */
    public UserDataVO findUserBySubjectAndIssuerDN(Admin admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException;

    /**
     * Finds a user by its subject DN.
     * @return UserDataVO or null if the user is not found.
     */
    public UserDataVO findUserBySubjectDN(Admin admin, String subjectdn) throws AuthorizationDeniedException;

    /**
     * Finds a users by subject email.
     * @return List of all matching UserDataVO, never null
     */
    public List<UserDataVO> findUserByEmail(Admin admin, String email) throws AuthorizationDeniedException;

    /**
     * Method that checks if user with specified users certificate exists in
     * database
     * 
     * @param subjectdn
     * @throws AuthorizationDeniedException if user doesn't exist
     */
    public void checkIfCertificateBelongToUser(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException;

    /**
     * Finds all users with a specified status.
     * 
     * @param status the status to look for, from 'UserData'.
     * @return Collection of UserDataVO
     */
    public Collection<UserDataVO> findAllUsersByStatus(Admin admin, int status) throws FinderException;

    /**
     * Finds all users registered to a specified CA.
     * 
     * @param caid the caid of the CA, from 'UserData'.
     * @return Collection of UserDataVO, or empty collection if the query is
     *         illegal or no users exist
     */
    public Collection<UserDataVO> findAllUsersByCaId(Admin admin, int caid);

    /**
     * Finds all batch users with a specified status and returns the first
     * UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @param status the status, from 'UserData'.
     * @return all UserDataVO objects or an empty list
     */
    public List<UserDataVO> findAllBatchUsersByStatusWithLimit(int status);

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
     * @param numberofrows the number of rows to fetch, use 0 for default
     *            UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT
     * @return a collection of UserDataVO.
     * @throws IllegalQueryException when query parameters internal rules isn't
     *            fulfilled.
     * @see org.ejbca.util.query.Query
     */
    public java.util.Collection<UserDataVO> query(Admin admin, org.ejbca.util.query.Query query, java.lang.String caauthorizationstring,
            java.lang.String endentityprofilestring, int numberofrows) throws IllegalQueryException;

    /**
     * Methods that checks if a user exists in the database having the given
     * EndEntityProfile id. This function is mainly for avoiding
     * desynchronization when a end entity profile is deleted.
     * 
     * @param endentityprofileid the id of end entity profile to look for.
     * @return true if EndEntityProfile id exists in UserData table.
     */
    public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid);

    /**
     * Methods that checks if a user exists in the database having the given
     * CertificateProfile id. This function is mainly for avoiding
     * desynchronization when a CertificateProfile is deleted.
     * 
     * @param certificateprofileid the id of CertificateProfile to look for.
     * @return true if certificateproileid exists in UserData table.
     */
    public boolean checkForCertificateProfileId(Admin admin, int certificateprofileid);

    /**
     * Methods that checks if a user exists in the database having the given
     * caid. This function is mainly for avoiding desynchronization when a CAs
     * is deleted.
     * 
     * @param caid the id of CA to look for.
     * @return true if caid exists in UserData table.
     */
    public boolean checkForCAId(Admin admin, int caid);

    /**
     * Methods that checks if a user exists in the database having the given
     * HardTokenProfile id. This function is mainly for avoiding
     * desynchronization when a HardTokenProfile is deleted.
     * 
     * @param profileid of HardTokenProfile to look for.
     * @return true if profileid exists in UserData table.
     */
    public boolean checkForHardTokenProfileId(Admin admin, int profileid);

    /**
     * Method checking if username already exists in database. WARNING: do not
     * use this method where an authorization check is needed, use findUser
     * there instead.
     * 
     * @return true if username already exists.
     */
    public boolean existsUser(Admin admin, String username);

    /**
     * Mark a user's certificate for key recovery and set the user status to
     * UserDataConstants.STATUS_KEYRECOVERY.
     * 
     * @param admin used to authorize this action
     * @param username is the user to key recover a certificate for
     * @param certificate is the certificate to recover the keys for. Use
     *            'null' to recovery the certificate with latest not before
     *            date.
     * @return true if the operation was successful
     */
    public boolean prepareForKeyRecovery(Admin admin, String username, int endEntityProfileId, Certificate certificate)
    		throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException;
    
    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @return Collection of UserDataVO
     */
    // TODO: Move to Local interface.
    public Collection<UserDataVO> findAllUsersWithLimit(Admin admin) throws FinderException;
    
    /**
     * Selects a list of specific list of UserDataVO entities, as filtered by
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
    public List<UserDataVO> findUsers(List<Integer> caIds, long timeModified, int status);

}
