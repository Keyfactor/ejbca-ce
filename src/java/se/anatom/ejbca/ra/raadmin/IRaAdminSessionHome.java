package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: IRaAdminSessionHome.java,v 1.4 2002-09-12 18:14:15 herrvendil Exp $
 */

public interface IRaAdminSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IRaAdminSessionRemote interface
     */

    IRaAdminSessionRemote create(Admin administrator) throws CreateException, RemoteException;

}

