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
 
package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.util.Properties;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;





/**
 * Interface contating methods that need to be implementet in order 
 * to have a custom publisher. All Custom publishers must implement this interface.
 * 
 * @version $Id: ICustomPublisher.java,v 1.2 2006-07-21 15:28:25 anatom Exp $
 */

public interface ICustomPublisher {
	
	/**
	 *  Method called to all newly created ICustomPublishers to set it up with
	 *  saved configuration.
	 */
	public abstract void init(Properties properties);

	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public abstract boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, ExtendedInformation extendedinformation)throws PublisherException;
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */ 
	public abstract boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)throws PublisherException;
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public abstract void revokeCertificate(Admin admin, Certificate cert, int reason)throws PublisherException;
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public abstract void testConnection(Admin admin) throws PublisherConnectionException;
	

}

