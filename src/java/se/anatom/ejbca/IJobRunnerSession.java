
package se.anatom.ejbca;

import java.rmi.RemoteException;
import se.anatom.ejbca.log.Admin;
/**
 * JobRunner session wraps around any class and is a general session bean
 * that can be used to launch a specified job.
 *
 * @version $Id: IJobRunnerSession.java,v 1.4 2003-01-12 17:16:27 anatom Exp $
 */
public interface IJobRunnerSession {
    public void run(Admin admin) throws RemoteException;
}
