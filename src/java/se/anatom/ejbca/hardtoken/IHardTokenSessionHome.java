package se.anatom.ejbca.hardtoken;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IHardTokenSessionHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IHardTokenSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IHardTokenSessionRemote create() throws CreateException, RemoteException;
}
