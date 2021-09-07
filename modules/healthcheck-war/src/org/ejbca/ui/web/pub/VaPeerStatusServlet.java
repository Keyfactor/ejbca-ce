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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * <p>Servlet used to check which VAs are in sync with the CA. Can be used by a load balancer to divert traffic from
 * OCSP responders which do not have the latest information.</p>
 *
 * <p>A VA is defined as out of sync if the peer publisher has at least one item in the queue older than X seconds
 * where X is configured in the GUI.</p>
 *
 * <p>X should be configured according to the formula <code>X < policyTime - monPollTime - monTimeout</code> where
 * <code>policyTime</code> is the maximum time is should take for an OCSP responder to be aware of revocation information
 * according to CP/CPS, <code>monPollTime</code> is how often the monitoring system is polling the CA, and
 * <code>monTimeout</code> is the timeout for a status request.</p>
 *
 * <p>Minimum recommended values for <code>monPollTime</code> and <code>monTimeout</code> is 5 seconds.</p>
 *
 * <p>If all peer publishers have items queued, the servlet returns an empty response to prevent the load
 * balancer from taking all OCSP responders out of operation at the same time.</p>
 *
 * <p>A request to the servlet performs executes the following database queries:</p>
 * <ul>
 *     <li>
 *         To look up healthcheck configuration for access control (this query may not be performed if EJBCA gets a cache-hit):
 *          <code>SELECT * FROM GlobalConfigurationData WHERE configurationId = ?</code>
 *     </li>
 *     <li>To determine which publishers are configured on the system:
 *          <code>SELECT * FROM PublisherData</code>
 *     </li>
 *     <li>For every peer publisher on the system:
 *          <code>SELECT c FROM (SELECT 0 AS ORDERING, COUNT(*) AS c FROM PublisherQueueData WHERE publisherId = ?
 *          AND publishStatus = 20 AND timeCreated < (timeNow - X) tmp ORDER BY tmp.ordering</code>
 *     </li>
 * </ul>
 *
 * <p>Example of request and response:</p>
 * <pre>
 * curl -s http://localhost:8080/ejbca/publicweb/healthcheck/vastatus | jq .
 * {
 *   "error": false,
 *   "outOfSync": [
 *     {
 *       "name": "VA Peer Publisher"
 *     }
 *   ]
 * }
 * </pre>
 *
 * <p>Authentication to the servlet is controlled by the property <code>healthcheck.authorizedips</code>.
 *
 * <p>The servlet is responding with the following HTTP status codes:</p>
 * <ul>
 *     <li>HTTP status code 200 (OK) if the requested publisher queue(s) are empty.</li>
 *     <li>HTTP status code 401 (Not Authorized) if the IP address of the requester is not authorized according to
 *     <code>healthcheck.authorizedips.</code></li>
 *     <li>HTTP status code 500 (Internal Server Error) if an exception was thrown when determining the status.</li>
 *     <li>HTTP status code 503 (Service Unavailable) if at least one publisher queue is <i>not</i> empty (VA out of
 *     sync).</li>
 * </ul>
 */
public class VaPeerStatusServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(VaPeerStatusServlet.class);
    private static final long serialVersionUID = 1L;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        final long startTime = System.currentTimeMillis();
        response.setContentType("application/json");
        if (isAuthorized(request)) {
            try {
                final AbstractMap.SimpleEntry<JSONObject, Integer> jsonAndResponseCode = createResponse(request.getParameter("name"));
                response.getWriter().write(jsonAndResponseCode.getKey().toJSONString());
                response.setStatus(jsonAndResponseCode.getValue());
            } catch (final Throwable error) {
                log.error("An unexpected error occurred when querying the VA status servlet: " + error.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug(error);
                }
                response.getWriter().write(errorResponseFrom(error.getMessage()));
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        } else {
            log.error("The IP " + request.getRemoteAddr() + " is not authorized.");
            response.getWriter().write(errorResponseFrom("Requests from " + request.getRemoteAddr() + " are not authorized."));
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
        if (log.isDebugEnabled()) {
            logAdditionalInformation(request, response, System.currentTimeMillis() - startTime);
        }
    }

    private void logAdditionalInformation(final HttpServletRequest request,
                                          final HttpServletResponse response,
                                          final long processingTime) {
        final List<String> parameters = request.getParameterMap()
                .entrySet()
                .stream()
                .map(x -> "(" + x.getKey() + ", " + Arrays.toString(x.getValue()) + ")")
                .collect(Collectors.toList());
        log.debug("Created response for " + request.getRemoteAddr() + " in " + processingTime + " ms.");
        log.debug("The request was: " + request.getMethod() + " " + request.getContextPath()
                + " with "  + (parameters.isEmpty() ? "no parameters" : "parameters " + StringUtils.join(parameters, ", ")) + ".");
        log.debug("The HTTP status code sent to the client was: " + response.getStatus());
    }

    private String errorResponseFrom(final String errorMessage) {
        final JSONObject errorResponse = new JSONObject();
        errorResponse.put("error", true);
        errorResponse.put("message", errorMessage);
        return errorResponse.toJSONString();
    }
    
    private boolean isAuthorized(final HttpServletRequest request) {
        final String[] authorizedIps = EjbcaConfiguration.getHealthCheckAuthorizedIps().split(";");
        if (log.isDebugEnabled()) {
            log.debug("Performing authorisation check for " + request.getRemoteAddr() +
                    ". The following IPs are authorized to this servlet: " + Arrays.toString(authorizedIps));
        }
        return ArrayUtils.contains(authorizedIps, "ANY") || ArrayUtils.contains(authorizedIps, request.getRemoteAddr());
    }

    /**
     * Create a JSON response and an HTTP status code.
     *
     * @param publisherName The name of a publisher the monitoring system is querying the status for, or null if
     *                      the monitoring system is querying for all VAs.
     * @return a JSON object and an HTTP status code to send back to the monitoring system.
     */
    private AbstractMap.SimpleEntry<JSONObject, Integer> createResponse(final String publisherName) {
        boolean atLeastOneVaInSync = false;
        final JSONArray outOfSync = new JSONArray();
        for (final AbstractMap.Entry<Integer, BasePublisher> entry : publisherSession.getAllPublishers().entrySet()) {
            final Integer publisherId = entry.getKey();
            final BasePublisher publisher = entry.getValue();
            if (StringUtils.equals("ignore", publisher.getDescription())) {
                // Make it possible to ignore specific publishers if running system tests
                // on an existing installation
                continue;
            }
            if (!isPublishingToVa(publisher)) {
                continue;
            }
            if (!publisherHasItemInQueue(publisherId)) {
                atLeastOneVaInSync = true;
                continue;
            }
            if (publisherName == null || StringUtils.equals(publisherName, publisher.getName())) {
                final JSONObject vaOutOfSync = new JSONObject();
                vaOutOfSync.put("name", publisher.getName());
                outOfSync.add(vaOutOfSync);
            }
        }
        // Sanity check, produce a log message on error level if the monitoring
        // system is querying the status of a VA using a publisher which does
        // not exist.
        if (publisherName != null && publisherSession.getPublisher(publisherName) == null) {
            log.error("The publisher with the name '" + publisherName + "' does not exist. I will return HTTP status " +
                    "code 200 for this request, but this may not be accurate. Please update the configuration for " +
                    "your monitoring system.");
        }
        final JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("error", false);
        jsonResponse.put("outOfSync", outOfSync);
        // Send the response back together with a status code.
        //     503 = Take VA(s) out of operation
        //     200 = Do nothing
        // If all VA nodes are out of sync, do not send a 503 response to the monitoring system
        // to avoid a load balancer from taking all OCSP responders out of operation at the same
        // time.
        if (!outOfSync.isEmpty() && atLeastOneVaInSync) {
            return new AbstractMap.SimpleEntry<>(jsonResponse, HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        } else {
            return new AbstractMap.SimpleEntry<>(jsonResponse, HttpServletResponse.SC_OK);
        }
    }

    private boolean publisherHasItemInQueue(final int publisherId) {
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final int[] numberOfQueuedItems = publisherQueueSession.getPendingEntriesCountForPublisherInIntervals(
                publisherId, new int[] { -1 }, new int[] { globalConfiguration.getVaStatusTimeConstraint() });
        if (log.isDebugEnabled()) {
            log.debug("Looking for any items older than " + globalConfiguration.getVaStatusTimeConstraint()
                    + " seconds, in the publisher queue for publisher with ID " + publisherId
                    + ". Number of such items found = " + numberOfQueuedItems[0] + ".");
        }
        return numberOfQueuedItems[0] > 0;
    }

    private boolean isPublishingToVa(final BasePublisher publisher) {
        if (publisher instanceof CustomPublisherContainer) {
            final CustomPublisherContainer customPublisherContainer = (CustomPublisherContainer) publisher;
            return StringUtils.endsWith(customPublisherContainer.getClassPath(), "PeerPublisher");
        }
        return false;
    }
}
