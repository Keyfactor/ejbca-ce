package se.anatom.ejbca.log;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionHome.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface ILogSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IRaAdminSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ILogSessionRemote create() throws RemoteException, CreateException, Exception;
}
