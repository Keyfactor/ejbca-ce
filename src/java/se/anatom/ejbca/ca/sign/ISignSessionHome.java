
package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;

/**
 * @version $Id: ISignSessionHome.java,v 1.3 2002-11-17 14:01:38 herrvendil Exp $
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
