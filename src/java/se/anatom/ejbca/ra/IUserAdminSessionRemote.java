package se.anatom.ejbca.ra;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.Collection;

import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.exception.NotFoundException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;


/**
 * Interface for User admin session
 *
 * @version $Id: IUserAdminSessionRemote.java,v 1.22 2003-07-24 08:43:31 anatom Exp $
 */
public interface IUserAdminSessionRemote extends javax.ejb.EJBObject {
    // Public constants
    public static final int MAXIMUM_QUERY_ROWCOUNT = SecConst.MAXIMUM_QUERY_ROWCOUNT; // The maximun number of rows passed back in a query.

    // Public methods

    /**
     * Adds a user in the database.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the password used for authentication.
     * @param subjectdn the DN the subject is given in his certificate.
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject or null.
     * @param clearpwd true if the password will be stored in clear form in the db, otherwise it is
     *        hashed.
     * @param endentityprofileid the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile that should be
     *        generated for the user.
     * @param type of user i.e administrator, keyrecoverable and/or sendnotification
     * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
     * @param hardtokenissuerid , if token should be hard, the id of the hard token issuer, else 0.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void addUser(Admin admin, String username, String password, String subjectdn,
        String subjectaltname, String email, boolean clearpwd, int endentityprofileid,
        int certificateprofileid, int type, int tokentype, int hardtokenissuerid)
        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException;

    /**
     * Changes data for a user in the database speciefied by username.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param password the password used for authentication.
     * @param dn the DN the subject is given in his certificate.
     * @param subjectaltname the Subject Alternative Name to be used.
     * @param email the email of the subject or null.
     * @param clearpwd true if the password will be stored in clear form in the db, otherwise it is
     *        hashed.
     * @param endentityprofileid the id number of the end entity profile bound to this user.
     * @param certificateprofileid the id number of the certificate profile that should be
     *        generated for the user.
     * @param type of user i.e administrator, keyrecoverable and/or sendnotification
     * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
     * @param hardtokenissuerid , if token should be hard, the id of the hard token issuer, else 0.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void changeUser(Admin admin, String username, String password, String subjectdn,
        String subjectaltname, String email, boolean clearpwd, int endentityprofileid,
        int certificateprofileid, int type, int tokentype, int hardtokenissuerid, int status)
        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException;

    /**
     * Deletes a user from the database. The users certificates must be revoked BEFORE this method
     * is called.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void deleteUser(Admin admin, String username)
        throws AuthorizationDeniedException, NotFoundException, FinderException, RemoveException, 
            RemoteException;

    /**
     * Changes status of a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void setUserStatus(Admin admin, String username, int status)
        throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
     * Method that revokes a user.
     *
     * @param admin the administrator pwrforming the action
     * @param username , the username to revoke.
     * @param reason the reason of revokation.
     */
    public void revokeUser(Admin admin, String username, int reason)
        throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
     * Method that revokes a users certificate and sets users status to revoked if all certificates
     * are revoked.
     *
     * @param admin the administrator pwrforming the action
     * @param certserno the certificate serial number of certificate
     * @param username the username to revoke.
     * @param reason the reason of revokation.
     */
    public void revokeCert(Admin admin, BigInteger certserno, String username, int reason)
        throws AuthorizationDeniedException, FinderException, RemoteException;

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
     * @param admin the administrator pwrforming the action
     * @param subjectdn
     *
     * @return UserAdminData or null if the user is not found.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public UserAdminData findUserBySubjectDN(Admin admin, String subjectdn)
        throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
     * Finds a user by its Email.
     *
     * @param admin the administrator pwrforming the action
     * @param subjectdn
     *
     * @return UserAdminData or null if the user is not found.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public UserAdminData findUserByEmail(Admin admin, String email)
        throws AuthorizationDeniedException, RemoteException;

    /**
     * Method that checks if user with specified users certificate exists in database and is set as
     * administrator.
     *
     * @param admin the administrator pwrforming the action
     * @param subjectdn
     *
     * @throws AuthorizationDeniedException if user isn't an administrator.
     * @throws EJBException if a communication or other error occurs.
     */
    public void checkIfCertificateBelongToAdmin(Admin admin, BigInteger certificatesnr)
        throws AuthorizationDeniedException, RemoteException;

    /**
     * Finds all users with a specified status.
     *
     * @param admin the administrator pwrforming the action
     * @param status the new status, from 'UserData'.
     *
     * @return Collection of UserAdminData
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ra.UserAdminData
     */
    public Collection findAllUsersByStatus(Admin admin, int status)
        throws FinderException, RemoteException;

    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     *
     * @param admin the administrator pwrforming the action
     *
     * @return Collection of UserAdminData
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ra.UserAdminData
     */
    public Collection findAllUsersWithLimit(Admin admin)
        throws FinderException, RemoteException;

    /**
     * Finds all users with a specified status and returns the first MAXIMUM_QUERY_ROWCOUNT.
     *
     * @param admin the administrator pwrforming the action
     * @param status the new status, from 'UserData'.
     * @param onlybatchusers only returns uses meant to be processed through batch tool.
     *
     * @return Collection of UserAdminData
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ra.UserAdminData
     */
    public Collection findAllUsersByStatusWithLimit(Admin admin, int status, boolean onlybatchusers)
        throws FinderException, RemoteException;

    /**
     * Starts an external service that may be needed bu user administration.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void startExternalService(String[] args) throws RemoteException;

    /**
     * Method to execute a customized query on the ra user data. The parameter query should be a
     * legal Query object.
     *
     * @param admin the administrator pwrforming the action
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     *
     * @return a collection of UserAdminData. Maximum size of Collection is defined i
     *         IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     *
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     *
     * @see se.anatom.ejbca.util.query.Query
     */
    public Collection query(Admin admin, Query query) throws IllegalQueryException, RemoteException;

    /**
     * Methods that checks if a user exists in the database having the given endentityprofileid.
     * This function is mainly for avoiding desyncronisation when end entity profile is deleted.
     *
     * @param admin the administrator pwrforming the action
     * @param endentityprofileid the id of profile to look for.
     *
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid)
        throws RemoteException;

    /**
     * Methods that checks if a user exists in the database having the given certificateprofileid.
     * This function is mainly for avoiding desyncronisation when a certificateprofile is deleted.
     *
     * @param admin the administrator pwrforming the action
     * @param certificateprofileid the id of certificateprofile to look for.
     *
     * @return true if certificaterofileid exists in userdatabase.
     */
    public boolean checkForCertificateProfileId(Admin admin, int certificaterofileid)
        throws RemoteException;

    // Functions used to save  Global Configuration

    /**
     * Saves global configuration to the database.
     *
     * @param admin the administrator pwrforming the action
     * @param blobalconfiguration global configuration object
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globalconfiguration)
        throws RemoteException;

    /**
     * Loads the global configuration from the database.
     *
     * @param admin the administrator pwrforming the action
     *
     * @return GlobalConfiguration
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public GlobalConfiguration loadGlobalConfiguration(Admin admin)
        throws RemoteException;
}
