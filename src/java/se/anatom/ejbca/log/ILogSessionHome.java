package se.anatom.ejbca.log;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: ILogSessionHome.java,v 1.2 2002-12-10 07:46:01 herrvendil Exp $
 */

public interface ILogSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IRaAdminSessionRemote interface
     */

    ILogSessionRemote create() throws RemoteException, CreateException, Exception;

}

