package se.anatom.ejbca.ca.publisher;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IPublisherSessionHome.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
 */

public interface IPublisherSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenSessionRemote interface
     */

    IPublisherSessionRemote create() throws CreateException, RemoteException;

}

