
package se.anatom.ejbca.ra;

import java.util.Collection;

import java.rmi.RemoteException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.UserAdminData;

/**
 *
 * @version $Id: IUserAdminSession.java,v 1.5 2002-03-26 12:39:34 anatom Exp $
 */
public interface IUserAdminSession {

   /**
    * Adds a user in the database.
    *
    * @param username the unique username.
    * @param password the password used for authentication.
    * @param dn the DN the subject is given in his certificate.
    * @param email the email of the subject or null.
    * @param type the type of entity (from 'SecConst').
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void addUser(String username, String password, String dn, String email, int type) throws RemoteException;

   /**
    * Deletes a user from the database. The users certificates must be revoked BEFORE this method is called.
    *
    * @param username the unique username.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void deleteUser(String username) throws RemoteException;

   /**
    * Changes status of a user.
    *
    * @param username the unique username.
    * @param status the new status, from 'UserData'.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setUserStatus(String username, int status) throws FinderException, RemoteException;

   /**
    * Sets a new password for a user.
    *
    * @param username the unique username.
    * @param password the new password for the user, NOT null.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setPassword(String username, String password) throws FinderException, RemoteException;

    /**
    * Sets a clear text password for a user.
    *
    * @param username the unique username.
    * @param password the new password to be stored in clear text. Setting password to 'null' effectively deletes any previous clear text password.
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void setClearTextPassword(String username, String password) throws FinderException, RemoteException;

   /**
    * Finds a user.
    *
    * @param username username.
    * @return UserAdminData or null if the user is not found.
    * @throws EJBException if a communication or other error occurs.
    */
    public UserAdminData findUser(String username) throws FinderException, RemoteException;

   /**
    * Finds all users with a specified status.
    *
    * @param status the new status, from 'UserData'.
    * @return Collection of UserAdminData
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findAllUsersByStatus(int status) throws RemoteException;

}
