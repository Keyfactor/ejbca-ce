package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;

/**
 * @version $Id: IRaAdminSessionLocalHome.java,v 1.3 2002-07-22 10:38:48 anatom Exp $
 */

public interface IRaAdminSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */

    IRaAdminSessionLocal create() throws CreateException;

}

