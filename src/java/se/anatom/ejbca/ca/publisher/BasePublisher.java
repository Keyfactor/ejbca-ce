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

import java.io.Serializable;
import java.security.cert.Certificate;

import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.ExtendedInformation;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

/**
 * BasePublisher is a basic class that should be inherited by all types
 * of publishers in the system.
 *  
 *
 * @version $Id: BasePublisher.java,v 1.5 2004-05-13 17:21:45 anatom Exp $
 */
public abstract class BasePublisher extends UpgradeableDataHashMap implements Serializable, Cloneable {
    // Default Values
    

    public static final String TRUE  = "true";
    public static final String FALSE = "false";

    // Protected Constants.
	public static final String TYPE                           = "type";
	
    protected static final String DESCRIPTION                    = "description";
		
    // Public Methods

    /**
     * Creates a new instance of CertificateProfile
     */
    public BasePublisher() {
      setDescription("");	       
  
    }

    // Public Methods mostly used by PrimeCard
    /**
     * Returns the description of publisher
     */
    public String getDescription() { return (String) data.get(DESCRIPTION);}

	/**
	 * Sets the description. 
	 */
	public void setDescription(String description){ data.put(DESCRIPTION, description); }

  
    
    // Abstact methods.
    
    /**
     * Publishes a certificate to a certificate store.
     *
     * @param incert The certificate to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param username Username of end entity owning the certificate.
     * @param password Password given to the user, may be null if no password exists for the user.
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     * @param extendedinformation contains extended information about the user, like picture, is null if no extendedinformation exists about the user.
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */    
    public abstract boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, ExtendedInformation extendedinformation) throws PublisherException;
	
    /**
     * Published a CRL to a CRL store.
     *
     * @param incrl The DER coded CRL to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */    
    public abstract boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) throws PublisherException;
    
    /**
     * Revokes a certificate (already revoked by the CA), the Publisher decides what to do, if
     * anything.
     *
     * @param cert The DER coded Certificate that has been revoked.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public abstract void revokeCertificate(Admin admin, Certificate cert, int reason) throws PublisherException;
    
    /**
     * Method used to test the connection to a publisher.
     * 
     * @param admin the administrator perfoming the test
     * @throws PublisherConnectionException when couldn't be set up correctly in any way.
     */
    public abstract void testConnection(Admin admin) throws PublisherConnectionException;
    

    public abstract Object clone() throws CloneNotSupportedException;

    
    public abstract float getLatestVersion();

    
    public void upgrade(){
    	// Performing upgrade rutines
    }
    
	

}
