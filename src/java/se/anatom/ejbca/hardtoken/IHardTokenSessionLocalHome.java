package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IHardTokenSessionLocalHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface IHardTokenSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IHardTokenSessionLocal interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IHardTokenSessionLocal create() throws CreateException;
}
