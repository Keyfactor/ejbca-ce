package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IRaAdminSessionLocalHome.java,v 1.6 2003-06-26 11:43:25 anatom Exp $
 */
public interface IRaAdminSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICertificateStoreSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IRaAdminSessionLocal create() throws CreateException;
}
