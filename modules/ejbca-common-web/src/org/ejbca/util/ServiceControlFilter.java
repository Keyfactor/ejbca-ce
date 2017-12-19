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

package org.ejbca.util;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AvailableProtocolsConfiguration;

/**
 * <p>This filter is responsible for disabling access to parts of EJBCA based
 * on the URL of the request and the current system configuration, which
 * together with some peer access rules are known as "Modular Protocol Configuration".
 * The purpose of Modular Protocol Configuration is to reduce the attack surface by
 * allowing an administrator to completely disable access to node-local services which
 * should not be used.</p>
 * <p>The servlet filter implemented by this class only filters incoming requests.
 * The URL of the request is matched against a service in EJBCA, such as the
 * CMP protocol or the RA web. If this service is disabled according to the policy
 * stored in system configuration, the request is filtered and an HTTP response with
 * error code 403 is sent back to the client. Otherwise, the request is let through
 * unaltered.
 * @version $Id$
 */
public class ServiceControlFilter implements Filter {
    private static final Logger log = Logger.getLogger(ServiceControlFilter.class);

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Override
    public void destroy() {

    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        final AvailableProtocolsConfiguration availableProtocolsConfiguration = (AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        final String protocol = getServiceNameMatchingRequest(httpRequest);

        if (protocol != null && !availableProtocolsConfiguration.getProtocolStatus(protocol)) {
            if (log.isDebugEnabled()) {
                log.debug("Access to service " + protocol + " is disabled. HTTP request " + httpRequest.getRequestURL() + " is filtered.");
            }
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "This service has been disabled.");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Access to service " + protocol + " is allowed. HTTP request " + httpRequest.getRequestURL() + " is let through.");
        }
        chain.doFilter(request, response);
    }

    private String getServiceNameMatchingRequest(final HttpServletRequest httpRequest) {
        for (AvailableProtocolsConfiguration.AvailableProtocols service : AvailableProtocolsConfiguration.AvailableProtocols.values()) {
            if (StringUtils.equals(httpRequest.getContextPath(), service.getContextPath())
                    && containsRequiredParameters(httpRequest.getParameterMap(), service.getParameterMap())) {
                return service.getName();
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Request " + httpRequest.getRequestURL() + " for unknown service is let through.");
        }
        return null;
    }

    /**
     * Checks if the GET parameters of a request stored in the map given as first argument contains the required
     * parameters stored in the map given as second argument.
     * @param requestParams the parameter map of all GET parameters
     * @param requiredParams the parameter map with required parameters
     * @return true if all required parameters are present in the request
     */
    private boolean containsRequiredParameters(final Map<String, String[]> requestParams, final Map<String, String[]> requiredParams) {
        if (requiredParams.isEmpty()) {
            return true;
        }

        for (final String key : requiredParams.keySet()) {
            final String[] requestValues = requestParams.get(key);
            final String[] requiredValues = requiredParams.get(key);

            // Ensure each required value is in the list of request values

            if (requestValues == null) {
                return false;
            }

            final List<String> requestValuesList = Arrays.asList(requestValues);

            for (int i = 0; i < requiredValues.length; ++i) {
                if (!requestValuesList.contains(requiredValues[i])) {
                    return false;
                }
            }
        }
        return true;
    }
}
