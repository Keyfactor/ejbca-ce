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

package org.ejbca.ui.web.pub.cluster;

import java.net.HttpURLConnection;
import java.net.URL;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.config.OcspConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome;

/**
 * External OCSP Health Checker. 
 * 
 * Does the following system checks.
 * 
 * * Not about to run out if memory
 * * Database connection can be established.
 * * All OCSPSignTokens are active if not set as offline.
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class ExtOCSPHealthCheck extends CommonHealthCheck {
	
	private static final Logger log = Logger.getLogger(ExtOCSPHealthCheck.class);

	private boolean doSignTest = OcspConfiguration.getHealthCheckSignTest();
	private boolean doValidityTest = OcspConfiguration.getHealthCheckCertificateValidity();

	@EJB
	private CertificateStoreOnlyDataSessionLocal certificateStoreOnlyDataSessionLocal;
	
	public void init(ServletConfig config) {
		super.init(config);
		log.debug("OCSPSignTest: '"+this.doSignTest+"'. OCSCertificateValidityTest: '"+this.doValidityTest+"'.");
	}
	
	public String checkHealth(HttpServletRequest request) {
		log.debug("Starting HealthCheck requested by : " + request.getRemoteAddr());
		String errormessage = "";
		
		errormessage += checkMaintenance();
		if( !errormessage.equals("") ) { 
			// if Down for maintenance do not perform more checks
			return errormessage; 
		} 
		errormessage += checkDB();
		if(errormessage.equals("")){
		  errormessage += checkMemory();								
		  errormessage += checkOCSPSignTokens();	
		}
		
		if(errormessage.equals("")){
			// everything seems ok.
			errormessage = null;
		}
		
		return errormessage;
	}

	private String checkDB(){
		log.debug("Checking database connection.");
		return certificateStoreOnlyDataSessionLocal.getDatabaseStatus();
	}

	/**
	 * Since the classes are deployed in a separate WAR, we cannot access the healtcheck directly.
	 */
	private String checkOCSPSignTokens() {
        try {
            URL url = new URL("http://127.0.0.1:8080/ejbca/publicweb/status/ocsp?healthcheck=true&doSignTest=" + this.doSignTest + "&doValidityTest=" + this.doValidityTest);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            int responseCode = con.getResponseCode();
            String responseMessage = con.getResponseMessage();
            if (responseCode != 200) {
                return "Unexpected result code " +responseCode+" for URL: '" + url + "'. Message was: '" + responseMessage+'\'';
            }
            return responseMessage;
        } catch (Exception e){
        	return "Network problems: '"+e.getMessage()+'\'';
        }
	}
}
