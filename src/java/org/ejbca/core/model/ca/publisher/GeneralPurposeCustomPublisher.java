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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.Certificate;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;


/**
 * This is an class used for testing and example purposes.
 * I supposed to illustrat how to implement a custom publisher to EJBCA 3.
 *  
 *
 * @version $Id: GeneralPurposeCustomPublisher.java,v 1.3 2007-03-13 11:22:27 anatom Exp $
 */
public class GeneralPurposeCustomPublisher implements ICustomPublisher{
    		
    private static Logger log = Logger.getLogger(GeneralPurposeCustomPublisher.class);

    private static final InternalResources intres = InternalResources.getInstance();

	protected static final String externalCommandPropertyName	= "application";
	protected static final String failOnErrorCodePropertyName	= "failOnErrorCode";
	protected static final String failOnStdErrPropertyName		= "failOnStandardError";
	
	private String externalCommandFileName	= null;
	private boolean failOnErrorCode			= true;
	private boolean failOnStdErr			= true;

    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public GeneralPurposeCustomPublisher() {}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
	 */
	public void init(Properties properties) {
		// This method sets up the communication with the publisher	
		log.debug("Initializing GeneralPurposeCustomPublisher");		

		// Extract system properties
		if ( properties.getProperty(failOnErrorCodePropertyName) != null )
			failOnErrorCode = properties.getProperty(failOnErrorCodePropertyName).equalsIgnoreCase("true");

		if ( properties.getProperty(failOnStdErrPropertyName) != null )
			failOnStdErr = properties.getProperty(failOnStdErrPropertyName).equalsIgnoreCase("true");

		if ( properties.getProperty(externalCommandPropertyName) != null )
			externalCommandFileName = properties.getProperty(externalCommandPropertyName);
		
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
	 * Writes the CRL to a temporary file and executes an external command (found in property "application") with
	 * the temporary file as argument. By default, a PublisherException is thrown if the external command returns
	 * with an errorlevel or outputs to stderr. The properties "failOnErrorCode" and "failOnStandardError" can be
	 * used to control when an exception should be thrown.
	 * 
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.ejbca.core.model.log.Admin, byte[], java.lang.String, int)
	 */
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) throws PublisherException {
        log.debug(">storeCRL, Storing CRL");

        // Verify initialization 
		if ( externalCommandFileName == null ) {
			String msg = intres.getLocalizedMessage("publisher.errormissingproperty", externalCommandPropertyName);
        	log.error(msg);
			throw new PublisherException(msg);
		}

		// Create temporary file
		File tempFile 			= null;
		FileOutputStream fos	= null;

		try {
			tempFile = File.createTempFile("GeneralPurposeCustomPublisher", ".tmp");
			fos = new FileOutputStream(tempFile);
			fos.write(incrl);
			fos.close();
		} catch (FileNotFoundException e) {
			String msg = intres.getLocalizedMessage("publisher.errortempfile");
        	log.error(msg, e);
        	throw new PublisherException(msg);
		} catch (IOException e) {
			tempFile.delete();
			String msg = intres.getLocalizedMessage("publisher.errortempfile");
        	log.error(msg, e);
        	throw new PublisherException(msg);
		}
		
		// Exec file from properties with the file as an argument
		String tempFileName = null;

		try {
			tempFileName = tempFile.getCanonicalPath();
			Process externalProcess = Runtime.getRuntime().exec( externalCommandFileName + " " +  tempFileName);
			BufferedReader stdError = new BufferedReader(new InputStreamReader(externalProcess.getErrorStream()));
			String stdErrorOutput = null;
			
			// Check errorcode and the external applications output to stderr 
			if ( ((externalProcess.waitFor() != 0) && failOnErrorCode) || (stdError.ready() && failOnStdErr )) {
				tempFile.delete();
				String errTemp = null;
				while ( stdError.ready() && (errTemp = stdError.readLine()) != null ) {
					if (stdErrorOutput == null) { 
						stdErrorOutput = errTemp;
					} else {
						stdErrorOutput += "\n" + errTemp;
					}
				}
								
				String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommandFileName);
				if ( stdErrorOutput != null ) {
						msg += " - " + stdErrorOutput;
				}
	        	log.error(msg);
				throw new PublisherException(msg);
			}
		} catch (IOException e) {
			tempFile.delete();
			String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommandFileName);
        	log.error(msg, e);
			throw new PublisherException(msg);
		} catch (InterruptedException e) {
			tempFile.delete();
			String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommandFileName);
        	log.error(msg, e);
			throw new PublisherException(msg);
		}
		
        // Remove temporary file
		if ( !tempFile.delete() )
		{
			String msg = intres.getLocalizedMessage("publisher.errordeletetempfile", tempFileName);
        	log.error(msg);
			throw new PublisherException(msg);
		}	
   
		return true;
	}

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#revokeCertificate(org.ejbca.core.model.log.Admin, java.security.cert.Certificate, int)
	 */
	public void revokeCertificate(Admin admin, Certificate cert, int reason) throws PublisherException {
        log.debug("revokeCertificate, Rekoving Certificate");
		
	}	

	/**
	 * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection(org.ejbca.core.model.log.Admin)
	 */
	public void testConnection(Admin admin) throws PublisherConnectionException {
        log.debug("testConnection, Testing connection");			
	}

	
	protected void finalize() throws Throwable {
        log.debug("finalize, closing connection");
		// This method closes the communication with the publisher.	
			
		super.finalize(); 
	}
	
}
