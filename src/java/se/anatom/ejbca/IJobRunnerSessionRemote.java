package se.anatom.ejbca;

import java.rmi.RemoteException;

import javax.ejb.EJBObject;

import se.anatom.ejbca.log.Admin;


/**
 * Remote interface for JobRunner session.
 *
 * @version $Id: IJobRunnerSessionRemote.java,v 1.3 2004-01-25 09:37:10 herrvendil Exp $
 */
public interface IJobRunnerSessionRemote extends EJBObject {

	/**
	 * Runs the job
	 *
	 * @param admin administrator running the job
	 *
	 * @throws RemoteException error
	 */
	public void run(Admin admin,String issuerdn) throws RemoteException;
	

}
