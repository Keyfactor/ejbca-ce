package se.anatom.ejbca.ra.authorization;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IAuthorizationSessionHome.java
 */
public interface IAuthorizationSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IAuthorizationSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IAuthorizationSessionRemote create() throws CreateException, RemoteException;
}
