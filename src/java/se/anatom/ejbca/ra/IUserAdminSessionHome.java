
package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;

import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: IUserAdminSessionHome.java,v 1.5 2002-09-12 18:14:16 herrvendil Exp $
 */
public interface IUserAdminSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IUserAdminSessionRemote interface
     */
    IUserAdminSessionRemote create(Admin administrator) throws CreateException, RemoteException;

}
