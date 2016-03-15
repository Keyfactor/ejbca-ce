/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.example.mypublisher;
 
import java.security.cert.Certificate;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;

import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;


/**
 * This is a class used for plugin testing and example purposes.
 * It is supposed to illustrate how to implement a custom publisher in EJBCA 5.
 * @version $Id$
 *
 */
public class MyPublisher implements ICustomPublisher{
    		
    private static Logger log = Logger.getLogger(MyPublisher.class);

    /**
     * Creates a new instance of MyPublisher
     */
    public MyPublisher() {}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
	 */
	public void init(Properties properties) {
	  log.debug("Initializing MyPublisher");
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.cesecore.authentication.tokens.AuthenticationToken, java.security.cert.Certificate, java.lang.String, java.lang.String, int, int)
	 */
	public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
        log.debug("MyPublisher, Storing Certificate for user: " + username);	
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.cesecore.authentication.tokens.AuthenticationToken, byte[], java.lang.String, int)
	 */
	public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        log.debug("MyPublisher, Storing CRL");
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
	 */
	public void testConnection() throws PublisherConnectionException {
        log.debug("MyPublisher, Testing connection");			
	}

	@Override
	public boolean willPublishCertificate(int status, int revocationReason) {
            log.debug("MyPublisher, willPublishCertificate with status " + status + " and revocation reason " + revocationReason);
            return true;
	}

	@Override
	public boolean isReadOnly() {
            return false;
	}

}

