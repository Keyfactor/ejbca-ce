package se.anatom.ejbca.log;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: ILogSessionHome.java,v 1.1 2002-09-12 17:12:13 herrvendil Exp $
 */

public interface ILogSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IRaAdminSessionRemote interface
     */

    ILogSessionRemote create() throws CreateException, Exception;

}

