package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ICertificateStoreSessionHome.java,v 1.5 2003-06-26 11:43:23 anatom Exp $
 */
public interface ICertificateStoreSessionHome extends javax.ejb.EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICertificateStoreSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ICertificateStoreSessionRemote create() throws CreateException, RemoteException;
}
