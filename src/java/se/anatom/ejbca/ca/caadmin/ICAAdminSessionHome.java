
package se.anatom.ejbca.ca.caadmin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;

/**
 * @version $Id: ICAAdminSessionHome.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
 */
public interface ICAAdminSessionHome extends javax.ejb.EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ICAAdminSessionLocal interface
     */
    ICAAdminSessionRemote create() throws CreateException, RemoteException;
}
