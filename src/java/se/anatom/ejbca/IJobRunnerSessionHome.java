package se.anatom.ejbca;

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Home interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionHome.java,v 1.4 2003-06-26 11:43:16 anatom Exp $
 */
public interface IJobRunnerSessionHome extends EJBHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IJobRunnerSessionRemote interface
     *
     * @throws CreateException
     * @throws RemoteException
     */
    IJobRunnerSessionRemote create() throws CreateException, RemoteException;
}
