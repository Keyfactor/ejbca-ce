
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;

/**
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.2 2002-06-04 14:37:07 anatom Exp $
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
