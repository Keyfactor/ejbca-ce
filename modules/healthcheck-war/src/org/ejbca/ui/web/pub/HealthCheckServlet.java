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

package org.ejbca.ui.web.pub;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.util.Properties;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.HealthCheckSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Servlet used to check the health of an EJBCA instance and can be used to
 * build a cluster using a loadbalancer.
 * 
 * Does the following system checks.
 * 
 * * If a maintenance file is specific and the property is set to true, this message will be returned
 * * Not about to run out if memory i below configurable value
 * * Database connection can be established.
 * * All CATokens are active, if not set as offline and not set to specifically not be monitored
 * * All Publishers can establish connection
 * * All active OcspKeyBindings can be used.
 * 
 * * Optionally you can configure the CAToken test to also make a test signature, not only check if the token status is active.
 * 
 * @version $Id$
 */
public class HealthCheckServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(HealthCheckServlet.class);
    private static final long serialVersionUID = 1L;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final SameRequestRateLimiter<String> rateLimiter = new SameRequestRateLimiter<String>();
    
    private String[] authIPs = null;
    private boolean anyIpAuthorized = false;

    private final long minfreememory = EjbcaConfiguration.getHealthCheckAmountFreeMem();
    private boolean checkPublishers = EjbcaConfiguration.getHealthCheckPublisherConnections();

    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private HealthCheckSessionLocal healthCheckSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;

    @Override
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
        initMaintenanceFile();
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        doGet(request, response);
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (isAuthorized(request, response)) {
            respond(getRateLimitedResult(request), response);
        }
    }
    
    private boolean isAuthorized(HttpServletRequest request, HttpServletResponse response) {
        String remoteIP = request.getRemoteAddr();
        if (remoteIP == null || remoteIP.length()>100) {
            remoteIP = "unknown";
        }
        if (anyIpAuthorized || ArrayUtils.contains(authIPs, remoteIP)) {
            return true;
        } else {
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "ERROR : Healthcheck request recieved from an non authorized IP: " + remoteIP);
            } catch (IOException e) {
                log.error("Problems generating unauthorized http response.", e);
            }
            log.error(intres.getLocalizedMessage("healthcheck.errorauth", remoteIP));
        }
        return false;
    }
    
    private String getRateLimitedResult(HttpServletRequest request) {
        final SameRequestRateLimiter<String>.Result result = rateLimiter.getResult();
        if (result.isFirst()) {
            try {
                result.setValue(doAllHealthChecks(request));
            } catch (Throwable t) { // NOPMD: we want to catch all possible strangeness
                result.setError(t);
            }
        } else if (log.isDebugEnabled()) {
            log.debug("Re-using health check answer from first concurrent request for this request to conserve server load.");
        }
        return result.getValue();
    }
    
    private void respond(String status, HttpServletResponse resp) {
        resp.setContentType("text/plain");
        try {
            final Writer out = resp.getWriter();
            if (status == null) {
                // Return ok message
                out.write(EjbcaConfiguration.getOkMessage());
            } else {
                // Check if we return a static error message or the more informative
                final String customErrorMessage = EjbcaConfiguration.getCustomErrorMessage();
                if (log.isDebugEnabled()) {
                    log.debug("Healthcheck returned error. Status='"+status+"', customErrorMessage='"+customErrorMessage+"'.");
                }
                if (customErrorMessage != null) {
                    status = customErrorMessage;
                }
                // Return fail message
                if (EjbcaConfiguration.getSendServerError()) {
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, status);
                } else {
                    out.write(status);
                }
            }
            out.flush();
            out.close();
        } catch (IOException e) {
            log.error("Error writing to Servlet Response.", e);
        }
    }
    
    public String doAllHealthChecks(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Starting HealthCheck requested by : " + request.getRemoteAddr());
        }
        // Start by checking if we are in maintance mode
        final Properties maintenanceProperties = getMaintenanceProperties();
        final String maintenancePropertyName = EjbcaConfiguration.getHealthCheckMaintenancePropertyName();
        if (maintenanceProperties != null && Boolean.valueOf(maintenanceProperties.getProperty(maintenancePropertyName))) {
            // Return directly without performing any more checks
            return "MAINT: " + maintenancePropertyName;
        }
        final StringBuilder sb = new StringBuilder(0);
        if (log.isDebugEnabled()) {
            log.debug("Checking database connection.");
        }
        sb.append(healthCheckSession.getDatabaseStatus());
        if (sb.length()==0) { 
            if (log.isDebugEnabled()) {
                log.debug("Checking JVM heap memory.");
            }
            // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
            final long maxAllocation = Runtime.getRuntime().maxMemory();
            // The total amount of memory allocated to the JVM.
            final long currentlyAllocation = Runtime.getRuntime().totalMemory();
            // Available memory of what is allocated by the JVM
            final long freeAllocated = Runtime.getRuntime().freeMemory();
            // Memory still not allocated by the JVM + available memory of what is allocated by the JVM
            final long currentFreeMemory = maxAllocation - currentlyAllocation + freeAllocated;
            if (log.isDebugEnabled()) {
                log.debug((100L*(maxAllocation-currentFreeMemory)/maxAllocation)+"% of the " + (maxAllocation/1048576L) + " MiB heap is currently used.");
            }
            if (minfreememory >= currentFreeMemory) {
                sb.append("\nMEM: Error Virtual Memory is about to run out, currently free memory :").append(String.valueOf(Runtime.getRuntime().freeMemory()));    
            }
            if (log.isDebugEnabled()) {
                log.debug("Checking CAs.");
            }
            sb.append(caAdminSession.healthCheck());
            if (checkPublishers) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking publishers.");
                }
                sb.append(publisherSession.testAllConnections());
            }
            if (log.isDebugEnabled()) {
                log.debug("Checking OcspKeyBindings.");
            }
            sb.append(ocspResponseGeneratorSession.healthCheck());
        }
        return sb.length()==0 ? null : sb.toString();
    }

    /** Create the maintenance file if it should be used and does not exists */
    private void initMaintenanceFile() {
        final String maintenanceFile = EjbcaConfiguration.getHealthCheckMaintenanceFile();
        if (StringUtils.isEmpty(maintenanceFile)) {
            log.debug("Maintenance file not specified, node will be monitored");
        } else {
            if (getMaintenanceProperties() == null) {
                log.info("Expected to find Maintenance File '"+ maintenanceFile + "'. File will be created.");
                OutputStream out = null;
                try {
                    out = new FileOutputStream("filename.properties");
                    new Properties().store(out, null);
                } catch (IOException e2) {
                    log.error("Could not create Maintenance File at: "+ maintenanceFile);
                } finally {
                    if (out != null) {
                        try {
                            out.close();                    
                        } catch (IOException e) {
                            log.error("Error closing file: ", e);
                        }
                    }
                }
            }
        }
    }
    
    /** @return the maintenance file as properties or null of the file does not exist */
    private Properties getMaintenanceProperties() {
        final String maintenanceFile = EjbcaConfiguration.getHealthCheckMaintenanceFile();
        if (!StringUtils.isEmpty(maintenanceFile)) {
            InputStream in = null;
            try {
                in = new FileInputStream(maintenanceFile);
                final Properties maintenanceProperties = new Properties();
                maintenanceProperties.load(in);
                return maintenanceProperties;
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
                }
            } finally {
                if (in != null) {
                    try {
                        in.close();                 
                    } catch (IOException e) {
                        log.error("Error closing file: ", e);
                    }
                }
            }
        }
        return null;
    }    
}
