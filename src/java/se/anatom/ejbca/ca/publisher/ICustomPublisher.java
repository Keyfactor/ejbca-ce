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
import java.util.Properties;

import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.ExtendedInformation;



/**
 * Interface contating methods that need to be implementet in order 
 * to have a custom publisher. All Custom publishers must implement this interface.
 * 
 * @version $Id: ICustomPublisher.java,v 1.3 2004-05-13 15:36:11 herrvendil Exp $
 */

public interface ICustomPublisher {
	
	/**
	 *  Method called to all newly created ICustomPublishers to set it up with
	 *  saved configuration.
	 */
	public abstract void init(Properties properties);

	/**
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */    
	public abstract boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, ExtendedInformation extendedinformation)throws PublisherException;
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */ 
	public abstract boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)throws PublisherException;
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */    
	public abstract void revokeCertificate(Admin admin, Certificate cert, int reason)throws PublisherException;
	
	/**
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher
	 */    
	public abstract void testConnection(Admin admin) throws PublisherConnectionException;
	

}

