
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;


/**
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.1 2002-05-26 11:12:12 anatom Exp $
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
