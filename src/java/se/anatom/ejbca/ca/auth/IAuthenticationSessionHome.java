
package se.anatom.ejbca.ca.auth;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;

/**
 * @version $Id: IAuthenticationSessionHome.java,v 1.3 2002-11-17 14:01:39 herrvendil Exp $
 */
public interface IAuthenticationSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IAuthenticationSessionRemote interface
     */
    IAuthenticationSessionRemote create() throws CreateException, RemoteException;
}
