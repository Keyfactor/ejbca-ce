package se.anatom.ejbca.ca.auth;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Remote home for authentication session
 *
 * @version $Id: IAuthenticationSessionHome.java,v 1.4 2003-06-26 11:43:22 anatom Exp $
 */
public interface IAuthenticationSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IAuthenticationSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IAuthenticationSessionRemote create() throws CreateException, RemoteException;
}
