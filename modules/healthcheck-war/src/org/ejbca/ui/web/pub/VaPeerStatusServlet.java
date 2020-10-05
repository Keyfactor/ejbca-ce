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
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.AbstractMap;

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
    private static final SameRequestRateLimiter<String> rateLimiter = new SameRequestRateLimiter<>();
    private String[] authIps = null;
    private boolean anyIpAuthorized = false;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
        authIps = EjbcaConfiguration.getHealthCheckAuthorizedIps().split(";");
        if (ArrayUtils.contains(authIps, "ANY")) {
            log.info("Any IP is authorized to the VA status servlet.");
            anyIpAuthorized = true;
        } else {
            log.info("The following IPs are authorized to the VA status servlet: " + authIps);
        }
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        if (isAuthorized(request)) {
            final String jsonResponse = getRateLimitedResult();
            response.setContentType("application/json");
            try (final Writer responseToMonitoringSystem = response.getWriter()) {
                responseToMonitoringSystem.write(jsonResponse);
            }
        } else {
            log.error("The IP " + request.getRemoteAddr() + " is not authorized.");
            final JSONObject errorResponse = new JSONObject();
            errorResponse.put("error", true);
            errorResponse.put("message", "Requests from " + request.getRemoteAddr() + " are not authorized.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, errorResponse.toJSONString());
        }
    }
    
    private boolean isAuthorized(final HttpServletRequest request) {
        return anyIpAuthorized || ArrayUtils.contains(authIps, request.getRemoteAddr());
    }
    
    private String getRateLimitedResult() {
        final SameRequestRateLimiter<String>.Result result = rateLimiter.getResult();
        if (result.isFirst()) {
            try {
                result.setValue(createResponse());
            } catch (final Throwable error) {
                result.setError(error);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Re-using previous answer to conserve server load.");
            }
        }
        return result.getValue();
    }

    private String createResponse() {
        boolean atLeastOneVaInSync = false;
        final JSONArray outOfSync = new JSONArray();
        for (final AbstractMap.Entry<Integer, BasePublisher> entry : publisherSession.getAllPublishers().entrySet()) {
            final Integer publisherId = entry.getKey();
            final BasePublisher publisher = entry.getValue();
            if (isPublishingToVa(publisher)) {
                if (publisherHasItemInQueue(publisherId)) {
                    final JSONObject vaOutOfSync = new JSONObject();
                    vaOutOfSync.put("name", publisher.getName());
                    outOfSync.add(vaOutOfSync);
                } else {
                    atLeastOneVaInSync = true;
                }
            }
        }
        final JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("error", false);
        if (atLeastOneVaInSync) {
            jsonResponse.put("outOfSync", outOfSync);
        } else {
            // If all VA nodes are out of sync, do not put any VAs in the response
            // to avoid the load balancer taking all OCSP responders out of operation
            // at the same time
            jsonResponse.put("outOfSync", new JSONArray());
        }
        return jsonResponse.toJSONString();
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
