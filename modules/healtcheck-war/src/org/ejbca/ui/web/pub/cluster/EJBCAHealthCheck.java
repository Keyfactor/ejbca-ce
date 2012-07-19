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

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.HealthCheckSessionLocal;

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
	
	private final CAAdminSessionLocal caAdminSession;
	private final PublisherSessionLocal publisherSession;

	public EJBCAHealthCheck(CAAdminSessionLocal caAdminSession, PublisherSessionLocal publisherSession, HealthCheckSessionLocal healthCheckSession) {
	    super(healthCheckSession);
	    this.caAdminSession = caAdminSession;
	    this.publisherSession = publisherSession;
	}
	
	public String checkHealth(HttpServletRequest request) {
		if (log.isDebugEnabled()) {
			log.debug("Starting HealthCheck requested by : " + request.getRemoteAddr());
		}
		final StringBuilder sb = new StringBuilder(0);
		checkMaintenance(sb);
		if( sb.length()>0 ) { 
			// if Down for maintenance do not perform more checks
			return sb.toString(); 
		} 
		checkDB(sb);
        if (sb.length()==0) { 
			checkMemory(sb);
			checkCAs(sb);
			if (checkPublishers) {
				checkPublishers(sb);
			}
		}
        if (sb.length()==0) {
            // everything seems ok.
            return null;
		}
		return sb.toString();
	}
		
	private void checkCAs(final StringBuilder sb){
		if (log.isDebugEnabled()) {
			log.debug("Checking CAs.");
		}
		sb.append(caAdminSession.healthCheck());
	}
	
	private void checkPublishers(final StringBuilder sb) {
		if (log.isDebugEnabled()) {
			log.debug("Checking publishers.");
		}
		sb.append(publisherSession.testAllConnections());
	}

    public void setCheckPublishers(boolean checkPublishers) {
        this.checkPublishers = checkPublishers;
    }
	
}
