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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * <p>This filter is responsible for disabling access to parts of EJBCA based
 * on the URL of the request and the current system configuration, which
 * is known as "Modular Protocol Configuration".
 * The purpose of Modular Protocol Configuration is to reduce the attack surface by
 * allowing an administrator to completely disable access to node-local services which
 * should not be used.</p>
 * <p>The servlet filter implemented by this class only filters incoming requests.
 * The URL of the request is matched against a service in EJBCA, such as the
 * CMP protocol or the Public web. If this service is disabled according to the policy
 * stored in system configuration, the request is filtered and an HTTP response with
 * error code 403 is sent back to the client. Otherwise, the request is let through
 * unaltered.
 * @version $Id$
 */
public class ServiceControlFilter implements Filter {
    private static final Logger log = Logger.getLogger(ServiceControlFilter.class);
    
    private AvailableProtocolsConfiguration availableProtocolsConfiguration;
    
    private String serviceName;

    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @Override
    public void destroy() {
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        serviceName = filterConfig.getInitParameter("serviceName");
        // Since this filter is referenced in ejbca-common-web module and that module is referenced by 
        // cmpHttpProxy module, to make cmpHttpProxy module deploy-able in JEE servers we initialize 
        // the globalConfigurationSession bean here instead of using the EJB annotation.
        globalConfigurationSession = new EjbLocalHelper().getGlobalConfigurationSession();
        if (log.isDebugEnabled()) {
            log.debug("Initialized service control filter for '" + serviceName + "'.");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;
        availableProtocolsConfiguration = (AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        
        if (httpRequest.getRequestURL().toString().contains("ejbca/swagger-ui")) {
            chain.doFilter(request, response);
            log.debug("Allowing service explicitly for Swagger UI");
        }
        else {
            if (!availableProtocolsConfiguration.getProtocolStatus(serviceName)) {
                if (log.isDebugEnabled()) {
                    log.debug("Access to service " + serviceName + " is disabled. HTTP request " + httpRequest.getRequestURL() + " is filtered.");
                }
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "This service has been disabled.");
                return;
            }

            if (log.isDebugEnabled()) {
                log.debug("Access to service " + serviceName + " is allowed. HTTP request " + httpRequest.getRequestURL() + " is let through.");
            }
            chain.doFilter(request, response);
        }
    }
}
