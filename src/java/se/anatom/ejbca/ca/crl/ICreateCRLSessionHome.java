package se.anatom.ejbca.ca.crl;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Home interface for Create CRL session.
 *
 * @version $Id: ICreateCRLSessionHome.java,v 1.1 2004-02-11 10:44:12 herrvendil Exp $
 */
public interface ICreateCRLSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IICreateCRLSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    ICreateCRLSessionRemote create() throws CreateException, RemoteException;
}
