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
 
package org.ejbca.core.model.ca.publisher;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EJBTools;
import org.cesecore.util.ExternalScriptsAllowlist;


/**
 * This is a class used for testing and example purposes.
 * It is supposed to illustrate how to implement a custom publisher in EJBCA.
 */
public class DummyCustomPublisher implements ICustomPublisher, Serializable {
    		
    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(DummyCustomPublisher.class);

    private CertificateWrapper certificate = null;

    
    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public DummyCustomPublisher() {}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
	 */
	public void init(Properties properties) {
	  log.debug("Initializing DummyCustomPublisher " + properties.getProperty(BasePublisher.DESCRIPTION, ""));
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.cesecore.authentication.tokens.AuthenticationToken, java.security.cert.Certificate, java.lang.String, java.lang.String, int, int)
	 */
	public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing Certificate for user: " + username);	
        this.certificate = EJBTools.wrap(incert);
        return true;
    }
    
    public Certificate getStoredCertificate() {
        return EJBTools.unwrap(certificate);
    }
	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.cesecore.authentication.tokens.AuthenticationToken, byte[], java.lang.String, int)
	 */
	public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        log.debug("DummyCustomPublisher, Storing CRL");
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
	 */
	public void testConnection() throws PublisherConnectionException {
        log.debug("DummyCustomPublisher, Testing connection");			
	}

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }
    
    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean storeOcspResponseData(OcspResponseData ocspResponseData) throws PublisherException {
        // Method not applicable for this publisher type!
        return false;
    }
	
    @Override
    public boolean isCallingExternalScript() {
        return false;        
    }

    @Override
    public void setExternalScriptsAllowlist(ExternalScriptsAllowlist allowList) {
        // Method not applicable for this publisher type!        
    }

}
