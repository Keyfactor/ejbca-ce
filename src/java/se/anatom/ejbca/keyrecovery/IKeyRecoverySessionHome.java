package se.anatom.ejbca.keyrecovery;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IKeyRecoverySessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IKeyRecoverySessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IKeyRecoverySessionRemote create() throws CreateException, RemoteException;
}
