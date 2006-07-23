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

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;


/**
 * This is an class used for testing and example purposes.
 * I supposed to illustrat how to implement a custom publisher to EJBCA 3.
 *  
 *
 * @version $Id: DummyCustomPublisher.java,v 1.3 2006-07-23 10:31:22 anatom Exp $
 */
public class DummyCustomPublisher implements ICustomPublisher{
    		
    private static Logger log = Logger.getLogger(DummyCustomPublisher.class);

    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public DummyCustomPublisher() {}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
	 */
	public void init(Properties properties) {
	  // This method sets up the communication with the publisher	
		
	  log.debug("Initializing DummyCustomPublisher");		
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.ejbca.core.model.log.Admin, java.security.cert.Certificate, java.lang.String, java.lang.String, int, int)
	 */
	public boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, ExtendedInformation extendedinformation) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing Certificate for user: " + username);	
        // Don't publish non-active certificates
        if (status != CertificateDataBean.CERT_ACTIVE) {
        	return true;
        }
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.ejbca.core.model.log.Admin, byte[], java.lang.String, int)
	 */
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing CRL");
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#revokeCertificate(org.ejbca.core.model.log.Admin, java.security.cert.Certificate, int)
	 */
	public void revokeCertificate(Admin admin, Certificate cert, int reason) throws PublisherException {
        log.debug("DummyCustomPublisher, Rekoving Certificate");
		
	}	

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection(org.ejbca.core.model.log.Admin)
	 */
	public void testConnection(Admin admin) throws PublisherConnectionException {
        log.debug("DummyCustomPublisher, Testing connection");			
	}

	
	protected void finalize() throws Throwable {
        log.debug("DummyCustomPublisher, closing connection");
		// This method closes the communication with the publisher.	
			
		super.finalize(); 
	}
	
}
