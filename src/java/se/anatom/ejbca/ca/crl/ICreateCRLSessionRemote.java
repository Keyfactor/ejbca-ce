package se.anatom.ejbca.ca.crl;

import java.rmi.RemoteException;

import javax.ejb.EJBObject;

import se.anatom.ejbca.log.Admin;


/**
 * CreateCRL Session bean is only used to create CRLs.
 *
 * @version $Id: ICreateCRLSessionRemote.java,v 1.1 2004-02-11 10:44:12 herrvendil Exp $
 */
public interface ICreateCRLSessionRemote extends EJBObject {

	/**
	 * Creates a new CRL for the given CA.
	 *
	 * @param admin administrator running the job
	 *
	 * @throws RemoteException error
	 */
	public void run(Admin admin,String issuerdn) throws RemoteException;
	
	
	/**
	 * Methods that checks if there is any CRLs that should be generated and then creates them.
	 *
	 * @param admin administrator 
	 *
     * @return the number of crls created.
	 * @throws RemoteException error
	 */	
	public int createCRLs(Admin admin)   throws RemoteException;
	
}
