package se.anatom.ejbca.hardtoken;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IHardTokenBatchJobSessionHome.java,v 1.3 2003-09-03 12:47:24 herrvendil Exp $
 */

public interface IHardTokenBatchJobSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenBatchJobSessionRemote interface
     */

    IHardTokenBatchJobSessionRemote create() throws CreateException, RemoteException;

}

