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

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherExistsException;
import se.anatom.ejbca.log.Admin;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IPublisherSessionRemote for docs.
 *
 * @version $Id: IPublisherSessionLocal.java,v 1.2 2004-04-16 07:38:55 anatom Exp $
 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
 */

public interface IPublisherSessionLocal extends javax.ejb.EJBLocalObject

{
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */    
	public boolean storeCertificate(Admin admin, Collection publisherids, Certificate incert, String username, String cafp, int status, int type);
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */        
	public boolean storeCRL(Admin admin, Collection publisherids, byte[] incrl, String cafp, int number);
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */    
	public void revokeCertificate(Admin admin, Collection publisherids, Certificate cert, int reason);
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */    
	public void testConnection(Admin admin, int publisherid)throws PublisherConnectionException;
	
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */

	public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException;


	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */

	public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException;

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */

	public void changePublisher(Admin admin, String name, BasePublisher publisher);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public void clonePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException;

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public void removePublisher(Admin admin, String name);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException;

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public Collection getAuthorizedPublisherIds(Admin admin);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */    
	public HashMap getPublisherIdToNameMap(Admin admin);


	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public BasePublisher getPublisher(Admin admin, String name);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public BasePublisher getPublisher(Admin admin, int id);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote	 
	 */
	
	public int getPublisherUpdateCount(Admin admin, int publisherid);


	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public int getPublisherId(Admin admin, String name);

	/**
	 * @see se.anatom.ejbca.ca.publisher.IPublisherSessionRemote
	 */
	public String getPublisherName(Admin admin, int id);

	

}

