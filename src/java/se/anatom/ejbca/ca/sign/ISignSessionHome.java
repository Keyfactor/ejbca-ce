
package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: ISignSessionHome.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 */
public interface ISignSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return ISignSessionRemote interface
     */
    ISignSessionRemote create() throws CreateException, RemoteException;
}
