
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;

/**
 * @version $Id: ICertificateStoreSessionHome.java,v 1.4 2002-11-17 14:01:21 herrvendil Exp $
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
