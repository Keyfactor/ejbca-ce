package se.anatom.ejbca;

import se.anatom.ejbca.log.Admin;


/**
 * JobRunner session wraps around any class and is a general session bean that can be used to
 * launch a specified job.
 *
 * @version $Id: IJobRunnerSessionLocal.java,v 1.1 2004-01-25 09:37:10 herrvendil Exp $
 */
public interface IJobRunnerSessionLocal extends javax.ejb.EJBLocalObject  {
    /**
     * Runs the job
     *
     * @param admin administrator running the job
     *
     */
    public void run(Admin admin,String issuerdn);
}
