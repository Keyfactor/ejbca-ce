package se.anatom.ejbca.keyrecovery;

import javax.ejb.CreateException;

/**
 * @version $Id: IKeyRecoverySessionLocalHome.java,v 1.1 2003-02-12 13:21:30 herrvendil Exp $
 */

public interface IKeyRecoverySessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenSessionLocal interface
     */

    IKeyRecoverySessionLocal create() throws CreateException;

}

