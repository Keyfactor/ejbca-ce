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
 
package se.anatom.ejbca.ca.publisher;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;

import javax.ejb.EJBException;

import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherExistsException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.ExtendedInformation;

/**
 *
 * @version $Id: IPublisherSessionRemote.java,v 1.3 2004-05-13 15:36:11 herrvendil Exp $
 */
public interface IPublisherSessionRemote extends javax.ejb.EJBObject {
    
	/**
	 * Stores the certificate to the given collection of publishers.
	 * See BasePublisher class for further documentation about function
	 * 
	 * @param publisherids a Collection (Integer) of publisherids. 
	 * 
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 * @return true if sucessfull result on all given publishers
	 */    
	public boolean storeCertificate(Admin admin, Collection publisherids, Certificate incert, String username, String password, String cafp, int status, int type, ExtendedInformation extendedinformation) throws RemoteException;
	
	/**
	 * Stores the crl to the given collection of publishers.
	 * See BasePublisher class for further documentation about function
	 * 
	 * @param publisherids a Collection (Integer) of publisherids. 
	 * 
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 * @return true if sucessfull result on all given publishers
	 */        
	public boolean storeCRL(Admin admin, Collection publisherids, byte[] incrl, String cafp, int number) throws RemoteException;
	
	/**
	 * Revokes the certificate in the given collection of publishers.
	 * See BasePublisher class for further documentation about function
	 * 
	 * @param publisherids a Collection (Integer) of publisherids. 
	 * 
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */    
	public void revokeCertificate(Admin admin, Collection publisherids, Certificate cert, int reason)throws RemoteException;
	
	/**
	 * Test the connection to of a publisher
	 * 
	 * @param publisherid the id of the publisher to test. 
	 * 
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */    
	public void testConnection(Admin admin, int publisherid)throws PublisherConnectionException, RemoteException;
		
	
	/**
	 * Adds a publisher to the database.
	 *
	 * @throws PublisherExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException, RemoteException;


	/**
	 * Adds a publisher to the database.
	 * Used for importing and exporting profiles from xml-files.
	 * 
	 * @throws PublisherExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException, RemoteException;

	/**
	 * Updates publisher data
	 *	 
	 * @throws EJBException if a communication or other error occurs.
	 */

	public void changePublisher(Admin admin, String name, BasePublisher publisher) throws RemoteException;

	/**
	 * Adds a publisher with the same content as the original.
	 *
	 * @throws PublisherExistsException if publisher already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void clonePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException, RemoteException;

	/**
	 * Removes a publisher from the database.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void removePublisher(Admin admin, String name) throws RemoteException;

	/**
	 * Renames a publisher
	 *
	 * @throws PublisherExistsException if publisher already exists.
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException, RemoteException;

	/**
	 * Retrives a Collection of id:s (Integer) to authorized publishers.
	 *
	 * @return Collection of id:s (Integer)
	 */
	public Collection getAuthorizedPublisherIds(Admin admin)throws RemoteException;

	/**
	 * Method creating a hashmap mapping publisher id (Integer) to publisher name (String).
	 */    
	public HashMap getPublisherIdToNameMap(Admin admin)throws RemoteException;


	/**
	 * Retrives a named publisher.
	 */
	public BasePublisher getPublisher(Admin admin, String name)throws RemoteException;

	/**
	 * Finds a publisher by id.
	 *
	 *
	 */
	public BasePublisher getPublisher(Admin admin, int id)throws RemoteException;

	/**
	 * Help method used by publisher proxys to indicate if it is time to
	 * update it's data.
	 *	 
	 */
	
	public int getPublisherUpdateCount(Admin admin, int publisherid)throws RemoteException;


	/**
	 * Returns a publisher id, given it's publishers name
	 *	 
	 *
	 * @return the id or 0 if the publisher cannot be found.
	 */
	public int getPublisherId(Admin admin, String name)throws RemoteException;

	/**
	 * Returns a publishers name given its id.
	 *
	 * @return the name or null if id doesnt exists
	 * @throws EJBException if a communication or other error occurs.
	 */
	public String getPublisherName(Admin admin, int id)throws RemoteException;
	
	
	

}

