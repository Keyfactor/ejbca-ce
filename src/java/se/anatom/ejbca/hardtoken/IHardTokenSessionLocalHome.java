package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;

/**
 * @version $Id: IHardTokenSessionLocalHome.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 */

public interface IHardTokenSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenSessionLocal interface
     */

    IHardTokenSessionLocal create() throws CreateException;

}

