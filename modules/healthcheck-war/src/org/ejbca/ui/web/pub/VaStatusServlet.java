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
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
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
import java.util.Collection;

/**
 * Servlet used to check which VAs are in sync with the CA.
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
        final JSONArray outOfSync = new JSONArray();
        for (final AbstractMap.Entry<Integer, BasePublisher> entry : publisherSession.getAllPublishers().entrySet()) {
            final Integer publisherId = entry.getKey();
            final BasePublisher publisher = entry.getValue();
            if (isPublishingToVa(publisher)) {
                // TODO Only get entries older than X seconds
                final Collection<PublisherQueueData> queuedItems = publisherQueueSession.getPendingEntriesForPublisherWithLimit(publisherId, 1);
                if (!queuedItems.isEmpty()) {
                    final JSONObject vaOutOfSync = new JSONObject();
                    vaOutOfSync.put("name", publisher.getName());
                    outOfSync.add(vaOutOfSync);
                }
            }
        }
        final JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("error", false);
        jsonResponse.put("outOfSync", outOfSync);
        // TODO If all VA nodes are out of sync, report but don't put anything in the outOfSync array, we
        //  want at least one OCSP responder up and running even if it's not up to date
        return jsonResponse.toJSONString();
    }

    private boolean isPublishingToVa(final BasePublisher publisher) {
        if (publisher instanceof CustomPublisherContainer) {
            final CustomPublisherContainer customPublisherContainer = (CustomPublisherContainer) publisher;
            return StringUtils.endsWith(customPublisherContainer.getClassPath(), "PeerPublisher");
        }
        return false;
    }
}
