package se.anatom.ejbca.authorization;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;

/**
 * @version $Id: IAuthorizationSessionHome.java
 */
public interface IAuthorizationSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IAuthorizationSessionRemote interface
     */

    IAuthorizationSessionRemote create() throws CreateException, RemoteException;

}

