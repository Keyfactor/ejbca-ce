/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ca.crl;

import java.rmi.RemoteException;

import javax.ejb.EJBObject;

import se.anatom.ejbca.log.Admin;


/**
 * CreateCRL Session bean is only used to create CRLs.
 *
 * @version $Id: ICreateCRLSessionRemote.java,v 1.2 2004-04-16 07:39:00 anatom Exp $
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
