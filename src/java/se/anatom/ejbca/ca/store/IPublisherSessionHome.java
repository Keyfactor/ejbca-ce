package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IPublisherSessionHome.java,v 1.2 2003-06-26 11:43:23 anatom Exp $
 */
public interface IPublisherSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IPublisherSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IPublisherSessionRemote create() throws CreateException, RemoteException;
}
