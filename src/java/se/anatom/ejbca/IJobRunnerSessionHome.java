
package se.anatom.ejbca;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;


/**
 * Home interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionHome.java,v 1.1.1.1 2001-11-15 14:58:13 anatom Exp $
 */
public interface IJobRunnerSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @throws RemoteException
     * @return IJobRunnerSessionRemote interface
     */
    IJobRunnerSessionRemote create() throws CreateException, RemoteException;
}
