package se.anatom.ejbca.ca.auth;

import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.log.Admin;

import javax.ejb.ObjectNotFoundException;


/**
 * Interface used for authenticating entities when issuing their certificates. Local interface for
 * EJB, unforturnately this must be a copy of the remote interface except that RemoteException is
 * not thrown.
 *
 * @version $Id: IAuthenticationSessionLocal.java,v 1.6 2003-06-26 11:43:22 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
 */
public interface IAuthenticationSessionLocal extends javax.ejb.EJBLocalObject {
    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
     */
    public UserAuthData authenticateUser(Admin administrator, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException;

    /**
     * @see se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote
     */
    public void finishUser(Admin administrator, String username, String password)
        throws ObjectNotFoundException;
}
