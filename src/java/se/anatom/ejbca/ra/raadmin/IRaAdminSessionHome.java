package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IRaAdminSessionHome.java,v 1.6 2003-06-26 11:43:25 anatom Exp $
 */
public interface IRaAdminSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IRaAdminSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IRaAdminSessionRemote create() throws CreateException, RemoteException;
}
