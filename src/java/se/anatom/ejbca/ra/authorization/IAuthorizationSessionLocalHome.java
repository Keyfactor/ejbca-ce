package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import se.anatom.ejbca.ra.GlobalConfiguration;

/**
 * @version $Id: IAuthorizationSessionLocalHome.java
 */

public interface IAuthorizationSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ICertificateStoreSessionRemote interface
     */

    IAuthorizationSessionLocal create() throws CreateException;

}

