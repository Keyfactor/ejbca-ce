
package se.anatom.ejbca.ca.auth;

import java.util.*;
import java.rmi.RemoteException;

/** Interface used for authenticating entities when issuing their certificates.
 *
 * @version $Id: IAuthenticationSession.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 */
public interface IAuthenticationSession {

   /**
    * Authenticates a user to the user database and returns the user DN.
    *
    * @param username unique username within the instance
    * @param password password for the user
    *
    * @return UserAuthData, never returns null
    * @throws EJBException if authentication fails or a communication or other error occurs.
    */
    public UserAuthData authenticateUser(String username, String password) throws RemoteException;

   /**
    * Set the status of a user to finished, called when a user has been successfully processed.
    * If possible sets users status to UserData.STATUS_GENERATED, which means that the user cannot be authenticated anymore.
    * NOTE: May not have any effect of user database is remote.
    *
    * @param username unique username within the instance
    * @param password password for the user
    *
    * @throws EJBException if a communication or other error occurs.
    */
    public void finishUser(String username, String password) throws RemoteException;
}
