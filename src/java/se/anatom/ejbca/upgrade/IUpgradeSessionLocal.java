package se.anatom.ejbca.upgrade;

import se.anatom.ejbca.log.Admin;

/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see IUpgradeSessionRemote for docs.
 *
 * @version $Id: IUpgradeSessionLocal.java,v 1.1 2004-04-10 10:15:33 anatom Exp $
 *
 * @see se.anatom.ejbca.ca.store.IUpgradeSessionRemote
 */
public interface IUpgradeSessionLocal extends javax.ejb.EJBLocalObject {
	
    /** Upgrades the database
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     * @throws RemoteException
     */
    public boolean upgrade(Admin admin);	

}
