
package se.anatom.ejbca;

import java.util.*;
import java.rmi.RemoteException;

/**
 * JobRunner session wraps around any class and is a general session bean
 * that can be used to launch a specified job.
 *
 * @version $Id: IJobRunnerSession.java,v 1.1.1.1 2001-11-15 14:58:13 anatom Exp $
 */
public interface IJobRunnerSession {
    public void run() throws RemoteException;
}
