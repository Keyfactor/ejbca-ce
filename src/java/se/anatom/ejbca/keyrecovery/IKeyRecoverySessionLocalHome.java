package se.anatom.ejbca.keyrecovery;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionLocalHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IKeyRecoverySessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenSessionLocal interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IKeyRecoverySessionLocal create() throws CreateException;
}
