
package se.anatom.ejbca.ca.auth;

import javax.ejb.ObjectNotFoundException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.log.Admin;

/** Interface used for authenticating entities when issuing their certificates.
/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown.
 *
 * @version $Id: IAuthenticationSessionLocal.java,v 1.4 2002-11-17 14:01:39 herrvendil Exp $
 * @see se.anatom.ejbca.auth.IAuthenticationSessionRemote
 */
public interface IAuthenticationSessionLocal extends javax.ejb.EJBLocalObject {

    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSession
     */
    public UserAuthData authenticateUser(Admin administrator, String username, String password) throws ObjectNotFoundException, AuthStatusException, AuthLoginException;
    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSession
     */
    public void finishUser(Admin administrator, String username, String password) throws ObjectNotFoundException;
}
