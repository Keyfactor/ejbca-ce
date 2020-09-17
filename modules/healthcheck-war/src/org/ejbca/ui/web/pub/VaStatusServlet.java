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
 * <p>Servlet used to check which VAs are in sync with the CA. A VA is defined as out of sync if the peer publisher
 * has at least one item in the queue older than X seconds where X is configured in the GUI.</p>
 *
 * <p>Can be used by a load balancer to divert traffic from OCSP responders which do not have the latest
 * information.</p>
 *
 * <p>If all peer publishers have items queued, the servlet returns an empty response to prevent the load
 * balancer from taking all OCSP responders out of operation at the same time.</p>
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
 */
public class VaStatusServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(VaStatusServlet.class);
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
            try (final Writer responseToLoadBalancer = response.getWriter()) {
                responseToLoadBalancer.write(jsonResponse);
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
