
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;

/**
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.4 2002-11-17 14:01:22 herrvendil Exp $
 */
public interface ICertificateStoreSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */
    ICertificateStoreSessionLocal create() throws CreateException;
}
