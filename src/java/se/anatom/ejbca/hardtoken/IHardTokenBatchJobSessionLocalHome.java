package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;

/**
 * @version $Id: IHardTokenBatchJobSessionLocalHome.java,v 1.3 2003-09-03 12:47:24 herrvendil Exp $
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

