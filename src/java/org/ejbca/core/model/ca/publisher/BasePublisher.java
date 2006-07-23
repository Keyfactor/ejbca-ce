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

import java.io.Serializable;
import java.security.cert.Certificate;

import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;



/**
 * BasePublisher is a basic class that should be inherited by all types
 * of publishers in the system.
 *  
 *
 * @version $Id: BasePublisher.java,v 1.3 2006-07-23 10:31:22 anatom Exp $
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
     * Publishes a certificate to a certificate store. If status is not active for the certificate, the publisher may choose
     * to not publish the certificate, for instance if revoke removes a certificate from LDAP,
     * re-publishing the certificate should not add it again if the status is revoked.
     *
     * @param incert The certificate to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param username Username of end entity owning the certificate.
     * @param password Password given to the user, may be null if no password exists for the user.
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     * @param revocationDate Date for revocation (of revoked), like System.currentTimeMillis(), or -1 if not revoked.
     * @param revocationReason reason for revocation from RevokedCertInfo, RevokedCertInfo.NOT_REVOKED if not revoked.
     * @param extendedinformation contains extended information about the user, like picture, is null if no extendedinformation exists about the user.
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */    
    public abstract boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, ExtendedInformation extendedinformation) throws PublisherException;
	
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
