
package se.anatom.ejbca.ca.auth;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: IAuthenticationSessionHome.java,v 1.2 2002-09-12 18:14:16 herrvendil Exp $
 */
public interface IAuthenticationSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IAuthenticationSessionRemote interface
     */
    IAuthenticationSessionRemote create(Admin administrator) throws CreateException, RemoteException;
}
