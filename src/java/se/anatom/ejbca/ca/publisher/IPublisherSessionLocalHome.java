package se.anatom.ejbca.ca.publisher;

import javax.ejb.CreateException;

/**
 * @version $Id: IPublisherSessionLocalHome.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
 */

public interface IPublisherSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IHardTokenSessionLocal interface
     */

    IPublisherSessionLocal create() throws CreateException;

}

