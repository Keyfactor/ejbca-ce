package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IHardTokenBatchJobSessionLocalHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IHardTokenBatchJobSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenBatchJobSessionLocal interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IHardTokenBatchJobSessionLocal create() throws CreateException;
}
