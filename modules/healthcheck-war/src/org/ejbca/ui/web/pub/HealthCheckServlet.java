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
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.HealthCheckSessionLocal;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

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
    
    /**
     * I hold all the query parameters to customize the health check.  
     * I can also be used as key in a map to allow for rate limiting
     * customized health checks.
     */
    static class QueryParameters {

        final private String[] caNames;
        final private boolean checkAllCas;
        final private boolean checkOcsp;
        final private boolean checkPublishers;
        final private Map<String, String> cryptoTokensAndKeys;

        public QueryParameters(HttpServletRequest request) {
            String[] caNames = request.getParameterValues("ca");
            // deal with possible null return
            if (caNames == null)
                caNames = new String[0];
            this.caNames = caNames;
            checkAllCas = caNames.length == 0;
            checkOcsp = safeGetParameter(request, "ocsp", true);
            checkPublishers = safeGetParameter(request, "publishers", EjbcaConfiguration.getHealthCheckPublisherConnections());
            cryptoTokensAndKeys = collectTokenAndKeyParameters(request);
        }
        
        /**
         * pair up all "tokenXYZ" and "keyXYZ" pairs as a list of token/key pairs for testing
         */
        private Map<String, String> collectTokenAndKeyParameters(HttpServletRequest request) {
            ArrayList<String> parameterNames = new ArrayList<>();
            request.getParameterNames().asIterator().forEachRemaining(parameterNames::add);

            Map<String, String> cryptoTokensAndKeys = new LinkedHashMap<>();
            for (String parameterName : parameterNames) {
                if (parameterName.startsWith("token")) {
                    String suffix = parameterName.substring("token".length());
                    if (parameterNames.contains("key" + suffix)) {
                        String tokenName = request.getParameter(parameterName);
                        String keyName = request.getParameter("key" + suffix);
                        if (tokenName != null && keyName != null) {
                            cryptoTokensAndKeys.put(tokenName, keyName);
                        }
                    }
                }
            }
            return cryptoTokensAndKeys;
        }

        public void log() {
            log.debug(String.format("Checking cas=%b ocsp=%b publishers=%b", checkAllCas, checkOcsp, checkPublishers));
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(caNames);
            result = prime * result + Objects.hash(checkAllCas, checkOcsp, checkPublishers, cryptoTokensAndKeys);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            QueryParameters other = (QueryParameters) obj;
            return Arrays.equals(caNames, other.caNames) && checkAllCas == other.checkAllCas && checkOcsp == other.checkOcsp
                    && checkPublishers == other.checkPublishers && cryptoTokensAndKeys.equals(cryptoTokensAndKeys);
        }
    }

    private static final Logger log = Logger.getLogger(HealthCheckServlet.class);
    private static final long serialVersionUID = 1L;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    // have one rate limiter per QueryParameter, since it customizes the response
    private static final ConcurrentHashMap<QueryParameters, SameRequestRateLimiter<String>> rateLimiter = new ConcurrentHashMap<>();
    
    private String[] authIPs = null;
    private boolean anyIpAuthorized = false;

    private final long minfreememory = EjbcaConfiguration.getHealthCheckAmountFreeMem();

    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private HealthCheckSessionLocal healthCheckSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;

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
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "ERROR : Healthcheck request received from an non authorized IP: " + remoteIP);
            } catch (IOException e) {
                log.error("Problems generating unauthorized http response.", e);
            }
            log.error(intres.getLocalizedMessage("healthcheck.errorauth", remoteIP));
        }
        return false;
    }
    
    private String getRateLimitedResult(HttpServletRequest request) {
        // if we've got multiple HealthChecks with the same query parameters at the same time, only do one
        final SameRequestRateLimiter<String>.Result result = rateLimiter
                .computeIfAbsent(new QueryParameters(request), t -> new SameRequestRateLimiter<>()).getResult();
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
    
    /**
     * Fetch a boolean query parameter from request, returning defaultValue if not present.
     */
    static private boolean safeGetParameter(HttpServletRequest request, String name, boolean defaultValue) {
        String value = request.getParameter(name);
        if (value == null)
            return defaultValue;
        return Boolean.parseBoolean(value);
    }
    
    public String doAllHealthChecks(HttpServletRequest request) {
        
        QueryParameters queryParameters = new QueryParameters(request);
        
        if (log.isDebugEnabled()) {
            log.debug("Starting HealthCheck requested by : " + request.getRemoteAddr());
            queryParameters.log();
        }
        // Start by checking if we are in maintenance mode
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
            if (queryParameters.checkAllCas) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking all CAs with 'include in health check' enabled.");
                }
                sb.append(caAdminSession.healthCheck());
            }
            // if checkAllCas not specified, maybe specific cas were
            else if (queryParameters.caNames.length > 0 && !queryParameters.caNames[0].equals("none")) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking specified CAs: " + String.join(",", queryParameters.caNames));
                }

                sb.append(caAdminSession.healthCheck(Arrays.asList(queryParameters.caNames)));
            }
            if (queryParameters.cryptoTokensAndKeys.size() > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking cryptotoken(s).");
                }
                sb.append(cryptoTokenHealthCheck(queryParameters.cryptoTokensAndKeys));
            }
            if (queryParameters.checkPublishers) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking publishers.");
                }
                sb.append(publisherSession.testAllConnections());
            }
            if (queryParameters.checkOcsp) {
                if (log.isDebugEnabled()) {
                    log.debug("Checking OcspKeyBindings.");
                }
                sb.append(ocspResponseGeneratorSession.healthCheck());
            }
            try {
                if(log.isDebugEnabled()) {
                    log.debug("Perfoming health check on audit logs.");
                }
                securityEventsLoggerSession.healthCheck();
            } catch (DatabaseProtectionException e) {
                sb.append("Could not perform a test signature on the audit log.");
            }
            
        }
        return sb.length()==0 ? null : sb.toString();
    }


    

    /**
     * Test the named cryptotoken(s) and key(s)
     * 
     * @return "" if no errors occurred, otherwise a descriptive error string.
     */
    private String cryptoTokenHealthCheck(Map<String, String> cryptoTokensAndKeys) {
        StringBuilder out = new StringBuilder();
        for (String cryptoTokenName : cryptoTokensAndKeys.keySet()) {
            String testKeyName = cryptoTokensAndKeys.get(cryptoTokenName);
            Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
            if (cryptoTokenId == null) {
                out.append("\nTOKEN: " + cryptoTokenName + " unknown");
            }
            CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
            if (cryptoToken == null) {
                out.append("\nTOKEN: " + cryptoTokenName + " unknown");
            }
            try {
                cryptoToken.testKeyPair(testKeyName);
            } catch (InvalidKeyException | CryptoTokenOfflineException e) {
                log.error("Test key failed for token = " + cryptoTokenName + " and key = " + testKeyName, e);
                out.append("\nTOKEN: Test key failed for token=" + cryptoTokenName + " key=" + testKeyName);
            }
        }
        return out.toString();
    }

    /** Create the maintenance file if it should be used and does not exists */
    private void initMaintenanceFile() {
        final String maintenanceFile = EjbcaConfiguration.getHealthCheckMaintenanceFile();
        if (StringUtils.isEmpty(maintenanceFile)) {
            log.debug("Maintenance file not specified, node will be monitored");
        } else {
            if (getMaintenanceProperties() == null) {
                log.info("Expected to find Maintenance File '"+ maintenanceFile + "'. File will be created.");
                try (final OutputStream out = new FileOutputStream(maintenanceFile)) {
                    new Properties().store(out, null);
                } catch (IOException e2) {
                    log.error("Could not create Maintenance File at: "+ maintenanceFile);
                }
            }
        }
    }
    
    /** @return the maintenance file as properties or null of the file does not exist */
    private Properties getMaintenanceProperties() {
        final String maintenanceFile = EjbcaConfiguration.getHealthCheckMaintenanceFile();
        if (!StringUtils.isEmpty(maintenanceFile)) {
            try (final InputStream in = new FileInputStream(maintenanceFile)) {
                final Properties maintenanceProperties = new Properties();
                maintenanceProperties.load(in);
                return maintenanceProperties;
            } catch (IOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not read Maintenance File. Expected to find file at: "+ maintenanceFile);
                }
            }
        }
        return null;
    }    
}
