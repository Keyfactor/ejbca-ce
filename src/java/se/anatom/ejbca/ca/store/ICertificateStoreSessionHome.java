
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: ICertificateStoreSessionHome.java,v 1.3 2002-09-12 18:14:16 herrvendil Exp $
 */
public interface ICertificateStoreSessionHome extends javax.ejb.EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */
    ICertificateStoreSessionRemote create(Admin administrator) throws CreateException, RemoteException;
}
