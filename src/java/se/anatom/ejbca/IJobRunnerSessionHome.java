
package se.anatom.ejbca;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.EJBHome;
import se.anatom.ejbca.log.Admin;

/**
 * Home interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionHome.java,v 1.2 2002-09-12 18:14:15 herrvendil Exp $
 */
public interface IJobRunnerSessionHome extends EJBHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @param administrator contains data about the administrator using the bean.
     * @throws CreateException
     * @throws RemoteException
     * @return IJobRunnerSessionRemote interface
     */
    IJobRunnerSessionRemote create(Admin administrator) throws CreateException, RemoteException;
}
