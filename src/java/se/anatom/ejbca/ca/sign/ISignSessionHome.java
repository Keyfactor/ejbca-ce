
package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: ISignSessionHome.java,v 1.2 2002-09-12 18:14:14 herrvendil Exp $
 */
public interface ISignSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ISignSessionRemote interface
     */
    ISignSessionRemote create(Admin administrator) throws CreateException, RemoteException;
}
