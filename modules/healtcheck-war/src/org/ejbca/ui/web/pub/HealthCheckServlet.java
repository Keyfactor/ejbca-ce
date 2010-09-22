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

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.ui.web.pub.cluster.IHealthCheck;
import org.ejbca.ui.web.pub.cluster.IHealthResponse;
import org.ejbca.util.CryptoProviderTools;

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
public class HealthCheckServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(HealthCheckServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private IHealthCheck healthcheck = null;
    private IHealthResponse healthresponse = null;

    private String[] authIPs = null;

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

        try {
            // Install BouncyCastle provider
            CryptoProviderTools.installBCProviderIfNotAvailable();

            authIPs = EjbcaConfiguration.getHealthCheckAuthorizedIps().split(";");

            healthcheck = (IHealthCheck) Thread.currentThread().getContextClassLoader().loadClass(config.getInitParameter("HealthCheckClassPath"))
                    .newInstance();
            healthcheck.init(config);

            healthresponse = (IHealthResponse) Thread.currentThread().getContextClassLoader().loadClass(
                    config.getInitParameter("HealthResponseClassPath")).newInstance();
            healthresponse.init(config);

        } catch (Exception e) {
            throw new ServletException(e);
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
        log.trace(">doPost()");
        check(request, response);
        log.trace("<doPost()");
    }

    // doPost

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
        log.trace(">doGet()");
        check(request, response);
        log.trace("<doGet()");
    }

    private void check(HttpServletRequest request, HttpServletResponse response) {
        boolean authorizedIP = false;
        String remoteIP = request.getRemoteAddr();
        if ((authIPs != null) && (authIPs.length > 0)) {
            for (int i = 0; i < authIPs.length; i++) {
                if (remoteIP.equals(authIPs[i])) {
                    authorizedIP = true;
                }
            }
        } else {
            String iMsg = intres.getLocalizedMessage("healthcheck.allipsauthorized");
            log.info(iMsg);
            authorizedIP = true;
        }

        if (authorizedIP) {
            healthresponse.respond(healthcheck.checkHealth(request), response);
        } else {
            if ((remoteIP == null) || (remoteIP.length() > 100)) {
                remoteIP = "unknown";
            }
            try {
                response
                        .sendError(HttpServletResponse.SC_UNAUTHORIZED, "ERROR : Healthcheck request recieved from an non authorized IP: " + remoteIP);
            } catch (IOException e) {
                log.error("Problems generating unauthorized http response.", e);
            }
            String iMsg = intres.getLocalizedMessage("healthcheck.errorauth", remoteIP);
            log.error(iMsg);
        }
    }

} // HealthCheckServlet
