
package se.anatom.ejbca;

import java.util.*;
import java.rmi.RemoteException;

/**
 * JobRunner session wraps around any class and is a general session bean
 * that can be used to launch a specified job.
 *
 * @version $Id: IJobRunnerSession.java,v 1.2 2002-09-12 18:14:15 herrvendil Exp $
 */
public interface IJobRunnerSession {
    public void run() throws RemoteException;
}
