package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.5 2003-06-26 11:43:23 anatom Exp $
 */
public interface ICertificateStoreSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICertificateStoreSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ICertificateStoreSessionLocal create() throws CreateException;
}
