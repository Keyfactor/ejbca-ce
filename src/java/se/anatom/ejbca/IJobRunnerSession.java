
package se.anatom.ejbca;

import java.util.*;
import java.rmi.RemoteException;
import se.anatom.ejbca.log.Admin;
/**
 * JobRunner session wraps around any class and is a general session bean
 * that can be used to launch a specified job.
 *
 * @version $Id: IJobRunnerSession.java,v 1.3 2002-11-17 14:01:39 herrvendil Exp $
 */
public interface IJobRunnerSession {
    public void run(Admin admin) throws RemoteException;
}
