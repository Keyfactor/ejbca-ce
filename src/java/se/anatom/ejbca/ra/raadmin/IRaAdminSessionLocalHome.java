package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import se.anatom.ejbca.log.Admin;
/**
 * @version $Id: IRaAdminSessionLocalHome.java,v 1.4 2002-09-12 18:14:15 herrvendil Exp $
 */

public interface IRaAdminSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */

    IRaAdminSessionLocal create(Admin administrator) throws CreateException;

}

