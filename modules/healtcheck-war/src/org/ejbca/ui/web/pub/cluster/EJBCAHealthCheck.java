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

import javax.ejb.CreateException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * EJBCA Health Checker. 
 * 
 * Does the following system checks.
 * 
 * * If a maintenance file is specific and the property is set to true, this message will be returned
 * * Not about to run out if memory i below configurable value
 * * Database connection can be established.
 * * All CATokens are active, if not set as offline and not set to specifically not be monitored
 * * All Publishers can establish connection
 * 
 * * Optionally you can configure the CAToken test to also make a test signature, not only check if the token status is active.
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class EJBCAHealthCheck extends CommonHealthCheck {
	
	private static Logger log = Logger.getLogger(EJBCAHealthCheck.class);

	private boolean checkPublishers = EjbcaConfiguration.getHealthCheckPublisherConnections();
	
	private CAAdminSession caAdminSession;
	private PublisherSession publisherSession;
	private CertificateStoreSession certificateStoreSession;

	
	public void init(ServletConfig config) {
		super.init(config);
		EjbLocalHelper ejb = new EjbLocalHelper();
		try {
			caAdminSession = ejb.getCAAdminSession();
			publisherSession = ejb.getPublisherSession();
			certificateStoreSession = ejb.getCertStoreSession();
		} catch (CreateException e) {
			throw new RuntimeException(e);
		}
		if(config.getInitParameter("CheckPublishers") != null){
			log.warn("CheckPublishers servlet parameter has been dropped. Use \"healthcheck.publisherconnections\" property instead.");
		}
		log.debug("CheckPublishers: "+checkPublishers);
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
		if(errormessage.equals("")) {
			errormessage += checkMemory();								
			errormessage += checkCAs();	

			if(checkPublishers){
				errormessage += checkPublishers();
			}
		}
		
		if(errormessage.equals("")){
			// everything seems ok.
			errormessage = null;
		}
		
		return errormessage;
	}
		
	private String checkDB(){
		log.debug("Checking database connection.");
		return certificateStoreSession.getDatabaseStatus();
	}

	private String checkCAs(){
		log.debug("Checking CAs.");
		return caAdminSession.healthCheck();
	}
	
	private String checkPublishers(){
		log.debug("Checking publishers.");
		return publisherSession.testAllConnections();
	}
	
}
