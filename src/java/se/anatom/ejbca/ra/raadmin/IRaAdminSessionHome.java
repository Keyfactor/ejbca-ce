package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * @version $Id: IRaAdminSessionHome.java,v 1.5 2002-11-17 14:01:39 herrvendil Exp $
 */

public interface IRaAdminSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IRaAdminSessionRemote interface
     */

    IRaAdminSessionRemote create() throws CreateException, RemoteException;

}

