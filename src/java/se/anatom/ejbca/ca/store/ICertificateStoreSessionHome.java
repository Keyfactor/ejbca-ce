
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: ICertificateStoreSessionHome.java,v 1.1.1.1 2001-11-15 14:58:16 anatom Exp $
 */
public interface ICertificateStoreSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */
    ICertificateStoreSessionRemote create() throws CreateException, RemoteException;
}
