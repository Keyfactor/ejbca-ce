
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;

/**
 * @version $Id: ICertificateStoreSessionHome.java,v 1.2 2002-06-04 14:37:07 anatom Exp $
 */
public interface ICertificateStoreSessionHome extends javax.ejb.EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */
    ICertificateStoreSessionRemote create() throws CreateException, RemoteException;
}
