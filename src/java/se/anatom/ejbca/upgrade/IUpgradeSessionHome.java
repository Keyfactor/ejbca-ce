package se.anatom.ejbca.upgrade;

import java.rmi.RemoteException;
import javax.ejb.CreateException;

/**
 * @version $Id: IUpgradeSessionHome.java,v 1.1 2004-04-10 10:15:33 anatom Exp $
 */
public interface IUpgradeSessionHome extends javax.ejb.EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IUpgradeSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IUpgradeSessionRemote create() throws CreateException, RemoteException;
}
