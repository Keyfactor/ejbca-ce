package se.anatom.ejbca.ra;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.Collection;

import javax.ejb.DuplicateKeyException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.exception.NotFoundException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;


/**
 * Interface for User admin session
 *
 * @version $Id: IUserAdminSessionRemote.java,v 1.27 2003-12-05 14:50:27 herrvendil Exp $
 */
public interface IUserAdminSessionRemote extends javax.ejb.EJBObject {
    // Public constants
    public static final int MAXIMUM_QUERY_ROWCOUNT = SecConst.MAXIMUM_QUERY_ROWCOUNT; // The maximun number of rows passed back in a query.

    // Public methods


   /**
    * Adds a user in the database.
    *
    * @param username the unique username.
    * @param password the password used for authentication.
    * @param dn the DN the subject is given in his certificate.
    * @param subjectaltname the Subject Alternative Name to be used.
    * @param email the email of the subject or null.
    * @param endentityprofileid the id number of the end entity profile bound to this user.
    * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
    * @param type of user i.e administrator, keyrecoverable and/or sendnotification
    * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
    * @param hardtokenissuerid, if token should be hard, the id of the hard token issuer, else 0.
    * @param caid, the id of the CA that should be used to issue the users certificate
    *
    * @throws AuthorizationDeniedException if admin is not allowed to add user.
    * @throws UserDoesntFullfillEndEntityProfile if user info does not fulfill requirements from the users end entity profile.
    * @throws DuplicateKeyException if a user with this username already exist.
    * @throws EJBException if a communication or other error occurs.
    */
    public void addUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email,  boolean clearpwd,
                        int endentityprofileid, int certificateprofileid, int type, int tokentype, int hardtokenissuerid, int caid)
                         throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, DuplicateKeyException, RemoteException;

    /**
    * Changes data for a user in the database speciefied by username.
    *
    * @param username the unique username.
    * @param password the password used for authentication.*
    * @param dn the DN the subject is given in his certificate.
    * @param subjectaltname the Subject Alternative Name to be used.
    * @param email the email of the subject or null.
    * @param endentityprofileid the id number of the end entity profile bound to this user.
    * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
    * @param type of user i.e administrator, keyrecoverable and/or sendnotification
    * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
    * @param hardtokenissuerid, if token should be hard, the id of the hard token issuer, else 0.
    * @param caid, the id of the CA that should be used to issue the users certificate
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void changeUser(Admin admin, String username,  String password, String subjectdn, String subjectaltname, String email, boolean clearpwd,
                        int endentityprofileid, int certificateprofileid, int type,
                        int tokentype, int hardtokenissuerid, int status, int caid)
                        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException;

   /**
    * Deletes a user from the database. The users certificates must be revoked BEFORE this method is called.
    *
    * @param username the unique username.
    *
    * @throws NotFoundException if the user does not exist
    * @throws RemoveException if the user could not be removed
    * @throws EJBException if a communication or other error occurs.
    */
    public void deleteUser(Admin admin, String username) throws AuthorizationDeniedException, NotFoundException, RemoveException, RemoteException;

   /**
    * Changes status of a user.
    *
    * @param username the unique username.
    * @param status the new status, from 'UserData'.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setUserStatus(Admin admin, String username, int status) throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
     * Method that revokes a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username , the username to revoke.
     * @param reason the reason of revokation.
     */
    public void revokeUser(Admin admin, String username,int reason) throws AuthorizationDeniedException,FinderException, RemoteException;

    /**
     * Method that revokes a users certificate and sets users status to revoked if all certificates
     * are revoked.
     *
     * @param admin the administrator pwrforming the action
     * @param certserno the certificate serial number of certificate
     * @param username the username to revoke.
     * @param reason the reason of revokation.
     */
    public void revokeCert(Admin admin, BigInteger certserno, String issuerdn, String username, int reason) throws AuthorizationDeniedException,FinderException, RemoteException;

    /**
     * Sets a new password for a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password for the user, NOT null.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void setPassword(Admin admin, String username, String password)
        throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException, 
            RemoteException;

    /**
     * Sets a clear text password for a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting password to 'null'
     *        effectively deletes any previous clear text password.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void setClearTextPassword(Admin admin, String username, String password)
        throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException, 
            RemoteException;

    /**
     * Finds a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username username.
     *
     * @return UserAdminData or null if the user is not found.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public UserAdminData findUser(Admin admin, String username)
        throws FinderException, RemoteException, AuthorizationDeniedException;

    /**
    * Finds a user by its subjectDN.
    *
    * @param subjectdn
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */

    public UserAdminData findUserBySubjectDN(Admin admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
    * Finds a user by its Email.
    *
    * @param email
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */

    public Collection findUserByEmail(Admin admin, String email) throws AuthorizationDeniedException, RemoteException;

    /**
    * Method that checks if user with specified users certificate exists in database and is set as administrator.
    *
    * @param subjectdn
    * @throws AuthorizationDeniedException if user isn't an administrator.
    * @throws EJBException if a communication or other error occurs.
    */

    public void checkIfCertificateBelongToAdmin(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException, RemoteException;

   /**
    * Finds all users with a specified status.
    *
    * @param status the new status, from 'UserData'.
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    * @see se.anatom.ejbca.ra.UserAdminData
    */
    public Collection findAllUsersByStatus(Admin admin, int status) throws FinderException, RemoteException;

   /**
    * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
    *
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    * @see se.anatom.ejbca.ra.UserAdminData
    */
    public Collection findAllUsersWithLimit(Admin admin) throws FinderException, RemoteException;
    
   /**
    * Finds all users with a specified status and returns the first MAXIMUM_QUERY_ROWCOUNT.
    *
    * @param status the new status, from 'UserData'.
    * @param onlybatchusers, only returns uses meant to be processed through batch tool.
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    * @see se.anatom.ejbca.ra.UserAdminData
    */
    public Collection findAllUsersByStatusWithLimit(Admin admin, int status, boolean onlybatchusers) throws FinderException, RemoteException;

    /**
    * Starts an external service that may be needed bu user administration.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void startExternalService(String args[]) throws RemoteException;

    /**
     * Method to execute a customized query on the ra user data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @return a collection of UserAdminData. Maximum size of Collection is defined i IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query
     */
     public Collection query(Admin admin, Query query, String caauthorizationstring, String endentityprofilestring) throws IllegalQueryException , RemoteException;

    /**
     * Methods that checks if a user exists in the database having the given caid. This function is mainly for avoiding
     * desyncronisation when a CA is deleted.
     *
     * @param caid the id of CA to look for.
     * @return true if caid exists in userdatabase.
     */
    public boolean checkForCAId(Admin admin, int caid)  throws RemoteException;
     
     
    /**
     * Methods that checks if a user exists in the database having the given endentityprofileid. This function is mainly for avoiding
     * desyncronisation when end entity profile is deleted.
     *
     * @param endentityprofileid the id of profile to look for.
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid)  throws RemoteException;

    /**
     * Methods that checks if a user exists in the database having the given certificateprofileid. This function is mainly for avoiding
     * desyncronisation when a certificateprofile is deleted.
     *
     * @param certificateprofileid the id of certificateprofile to look for.
     * @return true if certificaterofileid exists in userdatabase.
     */
    public boolean checkForCertificateProfileId(Admin admin, int certificaterofileid) throws RemoteException;

	/**
	 *  Method checking if username already exists in database.
	 * 
	 *  @return true if username already exists.
	 */
	public boolean existsUser(Admin admin, String username) throws RemoteException;
	
	/**
	 * Methods that checks if a user exists in the database having the given hard token profile id. This function is mainly for avoiding
	 * desyncronisation when a hard token profile is deleted.
	 *
	 * @param profileid of hardtokenprofile to look for.
	 * @return true if proileid exists in userdatabase.
	 */
	public boolean checkForHardTokenProfileId(Admin admin, int profileid) throws RemoteException;



}

