package se.anatom.ejbca.log;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionHome.java,v 1.4 2003-09-04 08:05:02 herrvendil Exp $
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

    ILogSessionRemote create() throws RemoteException, CreateException;

}

