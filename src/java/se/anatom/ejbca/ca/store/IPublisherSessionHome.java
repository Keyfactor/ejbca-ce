
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IPublisherSessionHome.java,v 1.1 2002-01-01 11:08:09 anatom Exp $
 */
public interface IPublisherSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IPublisherSessionRemote interface
     */
    IPublisherSessionRemote create() throws CreateException, RemoteException;
}
