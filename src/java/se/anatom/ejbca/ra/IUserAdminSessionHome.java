package se.anatom.ejbca.ra;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IUserAdminSessionHome.java,v 1.7 2003-06-26 11:43:24 anatom Exp $
 */
public interface IUserAdminSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IUserAdminSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IUserAdminSessionRemote create() throws CreateException, RemoteException;
}
