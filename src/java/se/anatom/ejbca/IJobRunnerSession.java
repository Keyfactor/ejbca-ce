package se.anatom.ejbca;

import java.rmi.RemoteException;

import se.anatom.ejbca.log.Admin;


/**
 * JobRunner session wraps around any class and is a general session bean that can be used to
 * launch a specified job.
 *
 * @version $Id: IJobRunnerSession.java,v 1.8 2004-01-08 14:31:26 herrvendil Exp $
 */
public interface IJobRunnerSession  {
    /**
     * Runs the job
     *
     * @param admin administrator running the job
     *
     * @throws RemoteException error
     */
    public void run(Admin admin,String issuerdn) throws RemoteException;
}
