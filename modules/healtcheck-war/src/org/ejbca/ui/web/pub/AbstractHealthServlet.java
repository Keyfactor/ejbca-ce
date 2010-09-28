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
 * @author mikek
 * 
 */
public abstract class AbstractHealthServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(AbstractHealthServlet.class);
    private static final long serialVersionUID = 1L;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

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

        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();

        authIPs = EjbcaConfiguration.getHealthCheckAuthorizedIps().split(";");

        if (config.getInitParameter("CheckPublishers") != null) {
            log.warn("CheckPublishers servlet parameter has been dropped. Use \"healthcheck.publisherconnections\" property instead.");
        }
        initializeServlet();
        getHealthCheck().init();
        getHealthResponse().init(config);

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
            getHealthResponse().respond(getHealthCheck().checkHealth(request), response);
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

}
