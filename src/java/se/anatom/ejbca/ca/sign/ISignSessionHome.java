package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Remote home interface
 *
 * @version $Id: ISignSessionHome.java,v 1.4 2003-06-26 11:43:23 anatom Exp $
 */
public interface ISignSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ISignSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ISignSessionRemote create() throws CreateException, RemoteException;
}
