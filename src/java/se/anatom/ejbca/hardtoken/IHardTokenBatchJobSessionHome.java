package se.anatom.ejbca.hardtoken;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IHardTokenBatchJobSessionHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IHardTokenBatchJobSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenBatchJobSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IHardTokenBatchJobSessionRemote create() throws CreateException, RemoteException;
}
