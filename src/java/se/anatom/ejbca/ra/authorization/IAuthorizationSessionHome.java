package se.anatom.ejbca.ra.authorization;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;

import se.anatom.ejbca.ra.GlobalConfiguration;

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

