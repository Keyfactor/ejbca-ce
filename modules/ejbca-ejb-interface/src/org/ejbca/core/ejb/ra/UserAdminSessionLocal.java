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

import javax.ejb.Local;

/**
 * Local interface for UserAdminSession.
 */
@Local
public interface UserAdminSessionLocal {
    /**
     * Implements IUserAdminSession::addUser. Implements a mechanism that uses
     * UserDataEntity Bean. Important, this method is old and shouldn't be used,
     * user addUser(..UserDataVO...) instead.
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param username
     *            the unique username.
     * @param password
     *            the password used for authentication.
     * @param subjectdn
     *            the DN the subject is given in his certificate.
     * @param subjectaltname
     *            the Subject Alternative Name to be used.
     * @param email
     *            the email of the subject or null.
     * @param clearpwd
     *            true if the password will be stored in clear form in the db,
     *            otherwise it is hashed.
     * @param endentityprofileid
     *            the id number of the end entity profile bound to this user.
     * @param certificateprofileid
     *            the id number of the certificate profile that should be
     *            generated for the user.
     * @param type
     *            of user i.e administrator, keyrecoverable and/or
     *            sendnotification, from SecConst.USER_XX.
     * @param tokentype
     *            the type of token to be generated, one of SecConst.TOKEN
     *            constants
     * @param hardwaretokenissuerid
     *            , if token should be hard, the id of the hard token issuer,
     *            else 0.
     * @param caid
     *            the CA the user should be issued from.
     * @throws WaitingForApprovalException
     * @throws UserDoesntFullfillEndEntityProfile
     * @throws AuthorizationDeniedException
     * @throws DuplicateKeyException
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws EjbcaException
     */
    public void addUser(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password, java.lang.String subjectdn,
            java.lang.String subjectaltname, java.lang.String email, boolean clearpwd, int endentityprofileid, int certificateprofileid, int type,
            int tokentype, int hardwaretokenissuerid, int caid) throws javax.ejb.DuplicateKeyException,
            org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * addUserFromWS is called from EjbcaWS if profile specifies merge data from
     * profile to user we merge them before calling addUser
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param userdata
     *            a UserDataVO object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd
     *            true if the password will be stored in clear form in the db,
     *            otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws DuplicateKeyException
     *             if user already exists
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
    public void addUserFromWS(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, boolean clearpwd)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            javax.ejb.DuplicateKeyException, org.ejbca.core.model.approval.WaitingForApprovalException,
            org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * Implements IUserAdminSession::addUser. Implements a mechanism that uses
     * UserDataEntity Bean.
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param userdata
     *            a UserDataVO object, the fields status, timecreated and
     *            timemodified will not be used.
     * @param clearpwd
     *            true if the password will be stored in clear form in the db,
     *            otherwise it is hashed.
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws DuplicateKeyException
     *             if user already exists
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
    public void addUser(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, boolean clearpwd)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            javax.ejb.DuplicateKeyException, org.ejbca.core.model.approval.WaitingForApprovalException,
            org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * Changes data for a user in the database speciefied by username.
     * Important, this method is old and shouldn't be used, user
     * changeUser(..UserDataVO...) instead.
     * 
     * @param username
     *            the unique username.
     * @param password
     *            the password used for authentication.*
     * @param subjectdn
     *            the DN the subject is given in his certificate.
     * @param subjectaltname
     *            the Subject Alternative Name to be used.
     * @param email
     *            the email of the subject or null.
     * @param endentityprofileid
     *            the id number of the end entity profile bound to this user.
     * @param certificateprofileid
     *            the id number of the certificate profile that should be
     *            generated for the user.
     * @param type
     *            of user i.e administrator, keyrecoverable and/or
     *            sendnotification
     * @param tokentype
     *            the type of token to be generated, one of SecConst.TOKEN
     *            constants
     * @param hardwaretokenissuerid
     *            if token should be hard, the id of the hard token issuer, else
     *            0.
     * @param status
     *            the status of the user, from UserDataConstants.STATUS_X
     * @param caid
     *            the id of the CA that should be used to issue the users
     *            certificate
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
     * @throws EJBException
     *             if a communication or other error occurs.
     * @deprecated use {@link #changeUser(Admin, UserDataVO, boolean)} instead
     */
    public void changeUser(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password, java.lang.String subjectdn,
            java.lang.String subjectaltname, java.lang.String email, boolean clearpwd, int endentityprofileid, int certificateprofileid, int type,
            int tokentype, int hardwaretokenissuerid, int status, int caid) throws org.ejbca.core.model.authorization.AuthorizationDeniedException,
            org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile, org.ejbca.core.model.approval.WaitingForApprovalException,
            org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * Implements IUserAdminSession::changeUser..
     * 
     * @param admin
     *            the administrator performing the action
     * @param userdata
     *            a UserDataVO object, timecreated and timemodified will not be
     *            used.
     * @param clearpwd
     *            true if the password will be stored in clear form in the db,
     *            otherwise it is hashed.
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
    public void changeUser(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, boolean clearpwd)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * Implements IUserAdminSession::changeUser..
     * 
     * @param admin
     *            the administrator performing the action
     * @param userdata
     *            a UserDataVO object, timecreated and timemodified will not be
     *            used.
     * @param clearpwd
     *            true if the password will be stored in clear form in the db,
     *            otherwise it is hashed.
     * @param fromWebService
     *            The service is called from webService
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile
     *             if data doesn't fullfil requirements of end entity profile
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     * @throws CADoesntExistsException
     *             if the caid of the user does not exist
     * @throws EjbcaException
     *             with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the
     *             SubjectDN Serialnumber already exists when it is specified in
     *             the CA that it should be unique.
     * @throws EJBException
     *             if the user does not exist
     */
    public void changeUser(org.ejbca.core.model.log.Admin admin, org.ejbca.core.model.ra.UserDataVO userdata, boolean clearpwd, boolean fromWebService)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.EjbcaException;

    /**
     * Deletes a user from the database. The users certificates must be revoked
     * BEFORE this method is called.
     * 
     * @param username
     *            the unique username.
     * @throws NotFoundException
     *             if the user does not exist
     * @throws RemoveException
     *             if the user could not be removed
     */
    public void deleteUser(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.NotFoundException, javax.ejb.RemoveException;

    /**
     * Resets the remaining failed login attempts counter to the user's max
     * login attempts value.
     * 
     * @param admin
     *            the administrator performing the action
     * @param username
     *            the unique username of the user
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to edit user
     * @throws FinderException
     *             if the entity does not exist
     */
    public void resetRemainingLoginAttempts(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException;

    /**
     * Decrements the remaining failed login attempts counter. If the counter
     * already was zero the status for the user is set to
     * {@link UserDataConstants#STATUS_GENERATED} if it wasn't that already.
     * This method does nothing if the counter value is set to UNLIMITED (-1).
     * 
     * @param admin
     *            the administrator performing the action
     * @param username
     *            the unique username of the user
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to edit user
     * @throws FinderException
     *             if the entity does not exist
     */
    public void decRemainingLoginAttempts(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException;

    /**
     * Decreases (the optional) request counter by 1, until it reaches 0.
     * Returns the new value. If the value is already 0, -1 is returned, but the
     * -1 is not stored in the database.
     * 
     * @param username
     *            the unique username.
     * @param status
     *            the new status, from 'UserData'.
     * @throws WaitingForApprovalException
     * @throws ApprovalException
     */
    public int decRequestCounter(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException;

    /**
     * Removes the certificate serial number from the user data.
     * 
     * @param admin
     * @param username
     *            the unique username.
     * @throws AuthorizationDeniedException
     * @throws FinderException
     * @throws ApprovalException
     * @throws WaitingForApprovalException
     */
    public void cleanUserCertDataSN(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException;

    /**
     * Changes status of a user.
     * 
     * @param username
     *            the unique username.
     * @param status
     *            the new status, from 'UserData'.
     * @throws ApprovalException
     *             if an approval already is waiting for specified action
     * @throws WaitingForApprovalException
     *             if approval is required and the action have been added in the
     *             approval queue.
     */
    public void setUserStatus(org.ejbca.core.model.log.Admin admin, java.lang.String username, int status)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException;

    /**
     * Sets a new password for a user.
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param username
     *            the unique username.
     * @param password
     *            the new password for the user, NOT null.
     */
    public void setPassword(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password)
            throws org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile, org.ejbca.core.model.authorization.AuthorizationDeniedException,
            javax.ejb.FinderException;

    /**
     * Sets a clear text password for a user.
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param username
     *            the unique username.
     * @param password
     *            the new password to be stored in clear text. Setting password
     *            to 'null' effectively deletes any previous clear text
     *            password.
     */
    public void setClearTextPassword(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password)
            throws org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile, org.ejbca.core.model.authorization.AuthorizationDeniedException,
            javax.ejb.FinderException;

    /**
     * Verifies a password for a user.
     * 
     * @param admin
     *            the administrator pwrforming the action
     * @param username
     *            the unique username.
     * @param password
     *            the password to be verified.
     */
    public boolean verifyPassword(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password)
            throws org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile, org.ejbca.core.model.authorization.AuthorizationDeniedException,
            javax.ejb.FinderException;

    public void revokeAndDeleteUser(org.ejbca.core.model.log.Admin admin, java.lang.String username, int reason)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException, javax.ejb.RemoveException, org.ejbca.core.model.ra.NotFoundException;

    /**
     * Method that revokes a user.
     * 
     * @param username
     *            the username to revoke.
     * @throws AlreadyRevokedException
     */
    public void revokeUser(org.ejbca.core.model.log.Admin admin, java.lang.String username, int reason)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.ra.AlreadyRevokedException;

    /**
     * Method that revokes a certificate for a user.
     * 
     * @param admin
     *            the administrator performing the action
     * @param certserno
     *            the serno of certificate to revoke.
     * @param username
     *            the username to revoke.
     * @param reason
     *            the reason of revokation, one of the RevokedCertInfo.XX
     *            constants.
     * @throws AlreadyRevokedException
     *             if the certificate was already revoked
     */
    public void revokeCert(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certserno, java.lang.String issuerdn, java.lang.String username,
            int reason) throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException,
            org.ejbca.core.model.approval.ApprovalException, org.ejbca.core.model.approval.WaitingForApprovalException,
            org.ejbca.core.model.ra.AlreadyRevokedException;

    /**
     * Reactivates the certificate with certificate serno.
     * 
     * @param admin
     *            the adminsitrator performing the action
     * @param certserno
     *            serial number of certificate to reactivate.
     * @param issuerdn
     *            the issuerdn of certificate to reactivate.
     * @param username
     *            the username joined to the certificate.
     * @throws WaitingForApprovalException
     * @throws ApprovalException
     * @throws AlreadyRevokedException
     */
    public void unRevokeCert(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certserno, java.lang.String issuerdn, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, javax.ejb.FinderException, org.ejbca.core.model.approval.ApprovalException,
            org.ejbca.core.model.approval.WaitingForApprovalException, org.ejbca.core.model.ra.AlreadyRevokedException;

    /**
     * Method that looks up the username and email address for a administrator
     * and returns the populated Admin object.
     * 
     * @param certificate
     *            is the administrators certificate
     */
    public org.ejbca.core.model.log.Admin getAdmin(java.security.cert.Certificate certificate);

    /**
     * Finds a user.
     * 
     * @param admin
     *            the administrator performing the action
     * @param username
     *            username.
     * @return UserDataVO or null if the user is not found.
     */
    public org.ejbca.core.model.ra.UserDataVO findUser(org.ejbca.core.model.log.Admin admin, java.lang.String username)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Finds a user by its subject and issuer DN.
     * 
     * @param admin
     * @param subjectdn
     * @param issuerdn
     * @return UserDataVO or null if the user is not found.
     */
    public org.ejbca.core.model.ra.UserDataVO findUserBySubjectAndIssuerDN(org.ejbca.core.model.log.Admin admin, java.lang.String subjectdn,
            java.lang.String issuerdn) throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Finds a user by its subject DN.
     * 
     * @param admin
     * @param subjectdn
     * @return UserDataVO or null if the user is not found.
     */
    public org.ejbca.core.model.ra.UserDataVO findUserBySubjectDN(org.ejbca.core.model.log.Admin admin, java.lang.String subjectdn)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Finds a user by its Email.
     * 
     * @param email
     * @return UserDataVO or null if the user is not found.
     */
    public java.util.Collection findUserByEmail(org.ejbca.core.model.log.Admin admin, java.lang.String email)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Method that checks if user with specified users certificate exists in
     * database
     * 
     * @deprecated This method no longer verifies the admin-flag of end entities
     *             since this feature was dropped in EJBCA 3.8.0
     * @param subjectdn
     * @throws AuthorizationDeniedException
     *             if user doesn't exist
     */
    public void checkIfCertificateBelongToAdmin(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certificatesnr, java.lang.String issuerdn)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Method that checks if user with specified users certificate exists in
     * database
     * 
     * @param subjectdn
     * @throws AuthorizationDeniedException
     *             if user doesn't exist
     */
    public void checkIfCertificateBelongToUser(org.ejbca.core.model.log.Admin admin, java.math.BigInteger certificatesnr, java.lang.String issuerdn)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException;

    /**
     * Finds all users with a specified status.
     * 
     * @param status
     *            the status to look for, from 'UserData'.
     * @return Collection of UserDataVO
     */
    public java.util.Collection findAllUsersByStatus(org.ejbca.core.model.log.Admin admin, int status) throws javax.ejb.FinderException;

    /**
     * Finds all users registered to a specified ca.
     * 
     * @param caid
     *            the caid of the CA, from 'UserData'.
     * @return Collection of UserDataVO, or empty collection if the query is
     *         illegal or no users exist
     */
    public java.util.Collection findAllUsersByCaId(org.ejbca.core.model.log.Admin admin, int caid);

    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @return Collection of UserDataVO
     */
    public java.util.Collection findAllUsersWithLimit(org.ejbca.core.model.log.Admin admin) throws javax.ejb.FinderException;

    /**
     * Finds all users with a specified status and returns the first
     * MAXIMUM_QUERY_ROWCOUNT.
     * 
     * @param status
     *            the new status, from 'UserData'.
     */
    public java.util.Collection findAllUsersByStatusWithLimit(org.ejbca.core.model.log.Admin admin, int status, boolean onlybatchusers)
            throws javax.ejb.FinderException;

    /**
     * Method to execute a customized query on the ra user data. The parameter
     * query should be a legal Query object.
     * 
     * @param query
     *            a number of statments compiled by query class to a SQL
     *            'WHERE'-clause statment.
     * @param caauthorizationstring
     *            is a string placed in the where clause of SQL query indication
     *            which CA:s the administrator is authorized to view.
     * @param endentityprofilestring
     *            is a string placed in the where clause of SQL query indication
     *            which endentityprofiles the administrator is authorized to
     *            view.
     * @param numberofrows
     *            the number of rows to fetch, use 0 for default
     *            UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT
     * @return a collection of UserDataVO. Maximum size of Collection is defined
     *         i IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException
     *             when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query
     */
    public java.util.Collection query(org.ejbca.core.model.log.Admin admin, org.ejbca.util.query.Query query, java.lang.String caauthorizationstring,
            java.lang.String endentityprofilestring, int numberofrows) throws org.ejbca.util.query.IllegalQueryException;

    /**
     * Methods that checks if a user exists in the database having the given
     * endentityprofileid. This function is mainly for avoiding desyncronisation
     * when a end entity profile is deleted.
     * 
     * @param endentityprofileid
     *            the id of end entity profile to look for.
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(org.ejbca.core.model.log.Admin admin, int endentityprofileid);

    /**
     * Methods that checks if a user exists in the database having the given
     * certificateprofileid. This function is mainly for avoiding
     * desyncronisation when a certificateprofile is deleted.
     * 
     * @param certificateprofileid
     *            the id of certificateprofile to look for.
     * @return true if certificateproileid exists in userdatabase.
     */
    public boolean checkForCertificateProfileId(org.ejbca.core.model.log.Admin admin, int certificateprofileid);

    /**
     * Methods that checks if a user exists in the database having the given
     * caid. This function is mainly for avoiding desyncronisation when a CAs is
     * deleted.
     * 
     * @param caid
     *            the id of CA to look for.
     * @return true if caid exists in userdatabase.
     */
    public boolean checkForCAId(org.ejbca.core.model.log.Admin admin, int caid);

    /**
     * Methods that checks if a user exists in the database having the given
     * hard token profile id. This function is mainly for avoiding
     * desyncronisation when a hard token profile is deleted.
     * 
     * @param profileid
     *            of hardtokenprofile to look for.
     * @return true if proileid exists in userdatabase.
     */
    public boolean checkForHardTokenProfileId(org.ejbca.core.model.log.Admin admin, int profileid);

    /**
     * Method checking if username already exists in database. WARNING: do not
     * use this method where an authorization check is needed, use findUser
     * there instead.
     * 
     * @return true if username already exists.
     */
    public boolean existsUser(org.ejbca.core.model.log.Admin admin, java.lang.String username);

    /**
     * Ḿark a user's certificate for key recovery and set the user status to
     * UserDataConstants.STATUS_KEYRECOVERY.
     * 
     * @param admin
     *            used to authorize this action
     * @param username
     *            is the user to key recover a certificate for
     * @param certificate
     *            is the certificate to recover the keys for. Use 'null' to
     *            recovery the certificate with latest not before date.
     * @return true if the operation was succesful
     * @throws WaitingForApprovalException
     * @throws ApprovalException
     * @throws AuthorizationDeniedException
     */
    public boolean prepareForKeyRecovery(org.ejbca.core.model.log.Admin admin, java.lang.String username, int endEntityProfileId,
            java.security.cert.Certificate certificate) throws org.ejbca.core.model.authorization.AuthorizationDeniedException,
            org.ejbca.core.model.approval.ApprovalException, org.ejbca.core.model.approval.WaitingForApprovalException;

}
