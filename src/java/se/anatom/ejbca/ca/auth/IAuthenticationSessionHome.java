
package se.anatom.ejbca.ca.auth;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IAuthenticationSessionHome.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
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
