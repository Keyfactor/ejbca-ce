
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: ICertificateStoreSessionLocalHome.java,v 1.3 2002-09-12 18:14:16 herrvendil Exp $
 */
public interface ICertificateStoreSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */
    ICertificateStoreSessionLocal create(Admin administrator) throws CreateException;
}
