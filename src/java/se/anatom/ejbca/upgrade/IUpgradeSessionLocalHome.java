package se.anatom.ejbca.upgrade;

import javax.ejb.CreateException;

/**
 * @version $Id: IUpgradeSessionLocalHome.java,v 1.1 2004-04-10 10:15:33 anatom Exp $
 */
public interface IUpgradeSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IUpgradeSessionLocalHome interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IUpgradeSessionLocal create() throws CreateException;
}
