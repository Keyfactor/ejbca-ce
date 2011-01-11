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

package org.ejbca.ui.web.pub;

import javax.ejb.EJB;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.ui.web.pub.cluster.EJBCAHealthCheck;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.ejbca.ui.web.pub.cluster.TextResponse;

/**
 * Servlet used to check the health of an EJBCA instance and can be used to
 * build a cluster using a loadbalancer.
 * 
 * This servlet should be configured with two init params: HealthCheckClassPath
 * : containing the classpath to the IHealthCheck class to be used to check.
 * HealthResponseClassPath : containing the classpath to the IHealthResponse
 * class to be used for the HTTPResponse
 * 
 * The loadbalancer or monitoring application should perform a GET request to
 * the url defined in web.xml.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class HealthCheckServlet extends AbstractHealthServlet {
    private static final long serialVersionUID = 1L;

    private IHealthCheck healthcheck = null;
    private TextResponse healthresponse = null;

    
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;


    @Override
    public void initializeServlet() {
        healthcheck = new EJBCAHealthCheck(caAdminSession, publisherSession, certificateStoreSession);
        healthresponse = new TextResponse();
    }

    @Override
    public IHealthCheck getHealthCheck() {
        return healthcheck;
    }

    @Override
    public TextResponse getHealthResponse() {
        return healthresponse;
    }

} 