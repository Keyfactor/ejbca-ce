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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.UpgradeableDataHashMap;



/**
 * BasePublisher is a basic class that should be inherited by all types
 * of publishers in the system.
 *  
 *
 * @version $Id$
 */
public abstract class BasePublisher extends UpgradeableDataHashMap implements Serializable, Cloneable {    

    private static final long serialVersionUID = -735659148394853025L;
    public static final String TRUE  = "true";
    public static final String FALSE = "false";
    
    public static final int PUBLISHER_BASE_VERSION = 1;
    public static final int CERTDATA_CAPABLE_PUBLISHER = 2; //Since 6.3.0

    // Protected Constants.
	public static final String TYPE                           = "type";
	
    protected static final String DESCRIPTION                    = "description";
    protected static final String ONLYUSEQUEUE                   = "onlyUseQueue";
    protected static final String KEEPPUBLISHEDINQUEUE           = "keepPublishedInQueue";
    protected static final String USEQUEUEFORCRLS                = "useQueueForCrls";
    protected static final String USEQUEUEFORCERTIFICATES        = "useQueueForCertificates";

    // Default values
    public static final boolean DEFAULT_ONLYUSEQUEUE 			 = false;
    
    // Values used for lookup that are not stored in the data hashmap
    private int id;
    private String name;
    
    // Public Methods

    /**
     * Creates a new instance of BasePublisher
     */
    public BasePublisher() {
      setDescription("");	       
      setOnlyUseQueue(DEFAULT_ONLYUSEQUEUE);
    }

    // Public Methods
    public int getPublisherId() { return id; }
    public String getName() { return name; }
    
    /** Sets the id. Used internally by PublisherSessionBean */ 
    public void setPublisherId(int id) { this.id = id; }
    /** Sets the name. Used internally by PublisherSessionBean */
    public void setName(String name) { this.name = name; }
    
    /**
     * Returns the description of publisher
     */
    public String getDescription() { return (String) data.get(DESCRIPTION);}

	/**
	 * Sets the description. 
	 */
	public void setDescription(String description){ data.put(DESCRIPTION, description); }


    /**
     * @return If only the publisher queue should be used instead of publishing directly.
     */
    public boolean getOnlyUseQueue() { return Boolean.TRUE.equals(data.get(ONLYUSEQUEUE));}
    
    /**
     * Sets whether only the publisher queue should be used instead of publishing directly.
     * @param onlyUseQueue true if only the queue should be used.
     */
    public void setOnlyUseQueue(boolean onlyUseQueue) { data.put(ONLYUSEQUEUE, Boolean.valueOf(onlyUseQueue));}

    /**
     * @return true if successfully published items should remain in the queue (with a different status) 
     */
    public boolean getKeepPublishedInQueue() { return Boolean.TRUE.equals(data.get(KEEPPUBLISHEDINQUEUE));}
    
    /**
     * Sets whether a successfully published items should remain in the queue (with a different status)
     * @param keepPublishedInQueue
     */
    public void setKeepPublishedInQueue(boolean keepPublishedInQueue) { data.put(KEEPPUBLISHEDINQUEUE, Boolean.valueOf(keepPublishedInQueue));}

    /**
     * @return true if CRLs should be kept in in the queue if publishing fails 
     */
    public boolean getUseQueueForCRLs() {
    	boolean ret = true;
    	Object o = data.get(USEQUEUEFORCRLS);
    	if (o != null) {
        	ret = Boolean.TRUE.equals(o);    		
    	}
    	return ret;
    }

    /**
     * Sets whether a CRLs should be put in the publish queue if publish failed
     * @param useQueueForCRLs
     */
    public void setUseQueueForCRLs(boolean useQueueForCRLs) { data.put(USEQUEUEFORCRLS, Boolean.valueOf(useQueueForCRLs));}

    /**
     * @return true if Certificates should be kept in in the queue if publishing fails 
     */
    public boolean getUseQueueForCertificates() {
    	boolean ret = true;
    	Object o = data.get(USEQUEUEFORCERTIFICATES);
    	if (o != null) {
        	ret = Boolean.TRUE.equals(o);    		
    	}
    	return ret;
    }

    /**
     * Sets whether a certificate should be put in the publish queue if publish failed
     * @param useQueueForCertificates
     */
    public void setUseQueueForCertificates(boolean useQueueForCertificates) { data.put(USEQUEUEFORCERTIFICATES, Boolean.valueOf(useQueueForCertificates));}

    /** Asks the publisher if the certificate with these parameters will be published. Used by the publisher queue to avoid
     * storing things that will never be published in the publisher queue.
     * 
     * @return default BasePublisher.willCertBePublished returns true, override in sub class to change behavior.
     */
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }
    
    // Abstact methods.
    
    /**
     * Publishes a certificate to a certificate store. If status is not active for the certificate, the publisher may choose
     * to not publish the certificate, for instance if revoke removes a certificate from LDAP,
     * re-publishing the certificate should not add it again if the status is revoked.
     *
     * To revoke a certificate (already revoked by the CA) call with status=CertificateDataBean.CERT_ACTIVE, the Publisher decides what to do, if
     * anything.
     * 
     * @param incert The certificate to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param username Username of end entity owning the certificate.
     * @param password Password given to the user, may be null if no password exists for the user.
     * @param userDN if a DN object is not found in the certificate use object from user data instead, can be null.
     * @param status Status of the certificate (from CertificateDataBean.CERT_ACTIVE, CERT_REVOKED etc).
     * @param type Type of certificate (from CertificateDataBean.CERTTYPE_ENDENTITY etc).
     * @param revocationDate Date for revocation (of revoked), like System.currentTimeMillis(), or -1 if not revoked.
     * @param revocationReason reason for revocation from RevokedCertInfo, RevokedCertInfo.NOT_REVOKED if not revoked.
     * @param extendedinformation contains extended information about the user, like picture, is null if no extendedinformation exists about the user.
     *
     * @return true if storage was successful.
     *
     * @throws PublisherException if a communication or other error occurs.
     */    
    public abstract boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException;

    /**
     * Publishes a CertificateData object in order to retain rowversion and  integrity protection data. Any publisher overriding this method must also override the getPublisherVersion
     * method and return a value > 1 from there. 
     * 
     * @param authenticationToken an authentication token
     * @param certificateData a complete CertificateData object
     * @param base64CertData a complete Base64CertData object
     * 
     * @return true if storage was successful.
     * 
     * @throws PublisherException if a communication or other error occurs.
     */
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException {
        throw new UnsupportedOperationException("This publisher has not implemented this method, and it has been called in error.");
    }
    
    /**
     *
     * @return the version of this publisher, giving a hint of what methods it supports. Publishers implementing newer functionality should override this method.
     */
    public int getPublisherVersion() {
        return PUBLISHER_BASE_VERSION;
    }

    /**
     * Published a CRL to a CRL store.
     *
     * @param incrl The DER coded CRL to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     * @param userDN if an DN object is not found in the certificate use object from user data instead, can be null.
     *
     * @return true if storage was successful.
     *
     * @throws PublisherException if a communication or other error occurs.
     */    
    public abstract boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException;
    
    /**
     * Method used to test the connection to a publisher.
     * 
     * @throws PublisherConnectionException when couldn't be set up correctly in any way.
     */
    public abstract void testConnection() throws PublisherConnectionException; // NOPMD: this is not a JUnit test
    

    @Override
    public abstract Object clone() throws CloneNotSupportedException;

    
    @Override
    public abstract float getLatestVersion();

    @Override
    public void upgrade(){
    	// Performing upgrade routines
    }
    
	

}
