package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;

/**
 * @version $Id: IHardTokenBatchJobSessionLocalHome.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 */

public interface IHardTokenBatchJobSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenBatchJobSessionLocal interface
     */

    IHardTokenBatchJobSessionLocal create() throws CreateException;

}

