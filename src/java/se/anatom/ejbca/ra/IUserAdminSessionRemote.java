package se.anatom.ejbca.ra;

import java.util.Collection;
import java.math.BigInteger;

import java.rmi.RemoteException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.util.query.Query;
import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.ra.authorization.AdminInformation;

/**
 *
 * @version $Id: IUserAdminSessionRemote.java,v 1.11 2002-11-12 08:25:36 herrvendil Exp $
 */
public interface IUserAdminSessionRemote extends javax.ejb.EJBObject {

    // Public constants
    public static final int MAXIMUM_QUERY_ROWCOUNT = 300; // The maximun number of rows passed back in a query.
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
    * @param administrator indicates if the user should be marked as administrator
    * @param keyrecoverable indicates if the users token should be key recoverable
    * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
    * @param hardtokenissuerid, if token should be hard, the id of the hard token issuer, else 0.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void addUser(String username, String password, String dn, String subjectaltname, String email,  boolean clearpwd,
                        int endentityprofileid, int certificateprofileid, boolean administrator, boolean keyrecoverable,
                        int tokentype, int hardtokenissuerid)
                         throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException;
    
    /**
    * Changes data for a user in the database speciefied by username.
    *
    * @param username the unique username.
    * @param dn the DN the subject is given in his certificate.
    * @param subjectaltname the Subject Alternative Name to be used.
    * @param email the email of the subject or null.
    * @param endentityprofileid the id number of the end entity profile bound to this user.
    * @param certificateprofileid the id number of the certificate profile that should be generated for the user.
    * @param administrator indicates if the user should be marked as administrator
    * @param keyrecoverable indicates if the users token should be key recoverable
    * @param tokentype the type of token to be generated, one of SecConst.TOKEN constants
    * @param hardtokenissuerid, if token should be hard, the id of the hard token issuer, else 0.
    *
    * @throws EJBException if a communication or other error occurs.
    */   
    public void changeUser(String username,  String dn, String subjectaltname, String email,  
                        int endentityprofileid, int certificateprofileid, boolean administrator, boolean keyrecoverable,
                        int tokentype, int hardtokenissuerid) 
                        throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, RemoteException;    

   /**
    * Deletes a user from the database. The users certificates must be revoked BEFORE this method is called.
    *
    * @param username the unique username.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void deleteUser(String username) throws AuthorizationDeniedException, RemoteException;

   /**
    * Changes status of a user.
    *
    * @param username the unique username.
    * @param status the new status, from 'UserData'.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setUserStatus(String username, int status) throws AuthorizationDeniedException, FinderException, RemoteException;

    /**
     * Method that revokes a user.
     *
     * @param username, the username to revoke.
     */    
    public void revokeUser(String username,int reason) throws AuthorizationDeniedException,FinderException, RemoteException;    

    /**
     * Method that revokes a users certificate and sets users status to revoked if all certificates are revoked.
     *
     * @param certserno, the certificate serial number of certificate
     * @param username, the username to revoke.
     * @param reason, the reason of revokation.
     */           
    public void revokeCert(BigInteger certserno, String username, int reason) throws AuthorizationDeniedException,FinderException, RemoteException;    

    /**
    * Sets a new password for a user.
    *
    * @param username the unique username.
    * @param password the new password for the user, NOT null.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setPassword(String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException,FinderException, RemoteException;

    /**
    * Sets a clear text password for a user.
    *
    * @param username the unique username.
    * @param password the new password to be stored in clear text. Setting password to 'null' effectively deletes any previous clear text password.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setClearTextPassword(String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException,FinderException, RemoteException;

   /**
    * Finds a user.
    *
    * @param username username.
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */
    public UserAdminData findUser(String username) throws FinderException, RemoteException, AuthorizationDeniedException;
    
    /**
    * Finds a user by its subjectDN.
    *
    * @param subjectdn
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */

    public UserAdminData findUserBySubjectDN(String subjectdn) throws AuthorizationDeniedException, FinderException, RemoteException;
    
    /**
    * Finds a user by its Email.
    *
    * @param subjectdn
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */    

    public UserAdminData findUserByEmail(String email) throws AuthorizationDeniedException, RemoteException;
    
    /**
    * Method that checks if user with specified userdn exists in database and is set as administrator.
    *
    * @param subjectdn
    * @throws AuthorizationDeniedException if user isn't an administrator.
    * @throws EJBException if a communication or other error occurs.
    */    
    
    public void checkIfSubjectDNisAdmin(String subjectdn) throws AuthorizationDeniedException, RemoteException;  

   /**
    * Finds all users with a specified status.
    *
    * @param status the new status, from 'UserData'.
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    * @see se.anatom.ejbca.ra.UserAdminData
    */
    public Collection findAllUsersByStatus(int status) throws AuthorizationDeniedException, FinderException, RemoteException;

   /**
    * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
    *
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    * @see se.anatom.ejbca.ra.UserAdminData
    */    
    public Collection findAllUsersWithLimit()  throws  FinderException, RemoteException;
    
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
     public Collection query(Query query) throws IllegalQueryException , RemoteException;    
     
    /** 
     * Methods that checks if a user exists in the database having the given endentityprofileid. This function is mainly for avoiding 
     * desyncronisation when end entity profile is deleted.
     *
     * @param endentityprofileid the id of profile to look for.
     * @return true if endentityprofileid exists in userdatabase.
     */
    public boolean checkForEndEntityProfileId(int endentityprofileid)  throws RemoteException;        
     
    /** 
     * Methods that checks if a user exists in the database having the given certificateprofileid. This function is mainly for avoiding 
     * desyncronisation when a certificateprofile is deleted.
     *
     * @param certificateprofileid the id of certificateprofile to look for.
     * @return true if certificaterofileid exists in userdatabase.
     */     
    public boolean checkForCertificateProfileId(int certificaterofileid) throws RemoteException;   
    
     // Functions used to save  Global Configuration
   /**
    * Saves global configuration to the database.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void saveGlobalConfiguration(GlobalConfiguration globalconfiguration) throws RemoteException;

   /**
    * Loads the global configuration from the database.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public GlobalConfiguration loadGlobalConfiguration() throws RemoteException;
    
    
   
}

