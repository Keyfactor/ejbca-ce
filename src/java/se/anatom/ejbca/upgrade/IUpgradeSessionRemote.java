package se.anatom.ejbca.upgrade;

import java.rmi.RemoteException;

import se.anatom.ejbca.log.Admin;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: IUpgradeSessionRemote.java,v 1.1 2004-04-10 10:15:33 anatom Exp $
 */
public interface IUpgradeSessionRemote extends javax.ejb.EJBObject {

    /** Upgrades the database
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     * @throws RemoteException
     */
    public boolean upgrade(Admin admin) throws RemoteException;

}
