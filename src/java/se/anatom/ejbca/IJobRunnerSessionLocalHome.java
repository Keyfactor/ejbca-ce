package se.anatom.ejbca;


import javax.ejb.CreateException;
import javax.ejb.EJBLocalHome;


/**
 * Local Home interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionLocalHome.java,v 1.1 2004-01-25 09:37:10 herrvendil Exp $
 */
public interface IJobRunnerSessionLocalHome extends EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IJobRunnerSessionRemote interface
     *
     * @throws CreateException 
     */
    IJobRunnerSessionLocal create() throws CreateException;
}
