package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IRaAdminSessionHome.java
 */

public interface IRaAdminSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IRaAdminSessionRemote interface
     */

    IRaAdminSessionRemote create() throws CreateException, RemoteException;

}

