
package se.anatom.ejbca.ca.auth;

import javax.ejb.ObjectNotFoundException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;

/** Interface used for authenticating entities when issuing their certificates.
/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown.
 *
 * @version $Id: IAuthenticationSessionLocal.java,v 1.1 2002-05-26 12:42:25 anatom Exp $
 * @see se.anatom.ejbca.auth.IAuthenticationSession
 */
public interface IAuthenticationSessionLocal extends javax.ejb.EJBLocalObject {

    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSession
     */ 
    public UserAuthData authenticateUser(String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSession
     */ 
    public void finishUser(String username, String password) throws ObjectNotFoundException;
}
