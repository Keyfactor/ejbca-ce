package se.anatom.ejbca.keyrecovery;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IKeyRecoverySessionHome.java,v 1.1 2003-02-12 13:21:30 herrvendil Exp $
 */

public interface IKeyRecoverySessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IKeyRecoverySessionRemote interface
     */

    IKeyRecoverySessionRemote create() throws CreateException, RemoteException;

}

