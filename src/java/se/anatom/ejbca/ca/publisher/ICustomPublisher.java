package se.anatom.ejbca.ca.publisher;

import java.security.cert.Certificate;
import java.util.Properties;

import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherException;
import se.anatom.ejbca.log.Admin;



/**
 * Interface contating methods that need to be implementet in order 
 * to have a custom publisher. All Custom publishers must implement this interface.
 * 
 * @version $Id: ICustomPublisher.java,v 1.1 2004-03-07 12:08:50 herrvendil Exp $
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
	public abstract boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type)throws PublisherException;
	
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

