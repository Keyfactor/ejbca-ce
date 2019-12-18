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
package org.ejbca.util.owaspcsrfguard;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.web.RequestHelper;

/**
 *  When using some filters, namely the CSRFGuard filter, it will mess up character encoding (if using something else than US-ASCII).
 *  We use this filter to set the correct, configured in EJBCA, (i.e. UTF-8 to support intl characters) character encoding.
 *  
 *  This filter also prevents using GET requests to operations in JSP pages, because OWASP CSRF guard does not protect GET requests the way we use it. 
 *  
 *  We don't use a WebFilter annotation here, because we must set it in web.xml in order to enforce the order filters are called.
 *  
 * @version $Id$
*/
public class EncodingFilter implements Filter {

    private static final Logger log = Logger.getLogger(EncodingFilter.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException,IOException {
        final HttpServletRequest httpreq = (HttpServletRequest) request;
        
        // The way we use OWASP CSRF Guard makes all POST requests to our form in the last remaining jsp pages protected against csrf attacks
        // it does however not protect GET requests to jsp pages, and service methods in jsp pages will respond to both GET and POST
        // therefore we will not allow any actions to jsp pages, that tries to perform anything (i.e. edituser etc) using anything else than POST
        // GET is still required in order to link to the pages to display them 
        log.trace("Using EncodingFilter to ensure that JSP actions can only be performed using HTTP POST");
        if (!httpreq.getMethod().equalsIgnoreCase("post")) {
            // It's not a POST request, check if it is an operation that tries to do something
            final Enumeration<String> params = httpreq.getParameterNames();
            while (params.hasMoreElements()) {
                final String param = (String) params.nextElement();
                if (StringUtils.contains(param, "button")) {
                    // It is an action to a JSP page clicking a button, i.e. trying to perform some action not just viewing the page
                    // for performing actions we require POST, so disallow this
                    log.warn("Refusing HTTP GET request containing parameter named '" + param + "'. Requests with parameters matching *button* must be done with HTTP POST.");
                    ((HttpServletResponse) response).sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                    return; // don't continue on down the chain
                }
                
            }
        }
        log.trace("Using EncodingFilter to set HTTP request character encoding");
        try {
            RequestHelper.setDefaultCharacterEncoding(httpreq);
        } catch (UnsupportedEncodingException e) {
            log.error("UnsupportedEncodingException: ", e);
        }
        //WARNING: do NOT swallow any Exception!!! If container can not see any exception, it will not redirect client to related error page.
        //You can catch Exceptions and print them, and you must throw them at last!
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {}

    @Override
    public void init(FilterConfig arg0) throws ServletException {}

}
