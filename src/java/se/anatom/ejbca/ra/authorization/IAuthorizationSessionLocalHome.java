package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IAuthorizationSessionLocalHome.java
 */
public interface IAuthorizationSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICertificateStoreSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IAuthorizationSessionLocal create() throws CreateException;
}
