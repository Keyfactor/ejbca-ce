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

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.ejbca.ui.web.pub.cluster.IHealthResponse;

/**
 * @version $Id$
 */
public abstract class AbstractHealthServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(AbstractHealthServlet.class);
    private static final long serialVersionUID = 1L;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final SameRequestRateLimiter<String> rateLimiter = new SameRequestRateLimiter<String>();

    private String[] authIPs = null;
    private boolean anyIpAuthorized = false;

    /**
     * Servlet init
     * 
     * @param config
     *            servlet configuration
     * 
     * @throws ServletException
     *             on error
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
        authIPs = EjbcaConfiguration.getHealthCheckAuthorizedIps().split(";");
        if (ArrayUtils.contains(authIPs, "ANY")) {
            log.info(intres.getLocalizedMessage("healthcheck.allipsauthorized"));
            anyIpAuthorized = true;
        }
        if (config.getInitParameter("CheckPublishers") != null) {
            log.warn("CheckPublishers servlet parameter has been dropped. Use \"healthcheck.publisherconnections\" property instead.");
        }
        initializeServlet();
        getHealthCheck().init();
    }

    public abstract IHealthCheck getHealthCheck();
    public abstract IHealthResponse getHealthResponse();
    
    /**
     * Override this method to inject members from the concrete servlet into the
     * Health Checker.
     * 
     */
    public abstract void initializeServlet();

    private void check(HttpServletRequest request, HttpServletResponse response) {
        String remoteIP = request.getRemoteAddr();
        if (remoteIP == null || remoteIP.length()>100) {
            remoteIP = "unknown";
        }
        if (anyIpAuthorized || ArrayUtils.contains(authIPs, remoteIP)) {
            final SameRequestRateLimiter<String>.Result result = rateLimiter.getResult();
            if (result.isFirst()) {
                result.setValue(getHealthCheck().checkHealth(request));
            }
            getHealthResponse().respond(result.getValue(), response);
        } else {
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "ERROR : Healthcheck request recieved from an non authorized IP: " + remoteIP);
            } catch (IOException e) {
                log.error("Problems generating unauthorized http response.", e);
            }
            log.error(intres.getLocalizedMessage("healthcheck.errorauth", remoteIP));
        }
    }

    /**
     * Handles HTTP POST
     * 
     * @param request
     *            servlet request
     * @param response
     *            servlet response
     * 
     * @throws IOException
     *             input/output error
     * @throws ServletException
     *             on error
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		if (log.isTraceEnabled()) {
			log.trace(">doPost()");
		}
        check(request, response);
		if (log.isTraceEnabled()) {
			log.trace("<doPost()");
		}
    }

    /**
     * Handles HTTP GET
     * 
     * @param request
     *            servlet request
     * @param response
     *            servlet response
     * 
     * @throws IOException
     *             input/output error
     * @throws ServletException
     *             on error
     */
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		if (log.isTraceEnabled()) {
			log.trace(">doGet()");
		}
        check(request, response);
		if (log.isTraceEnabled()) {
			log.trace("<doGet()");
		}
    }

}
