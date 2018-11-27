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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.RequestHelper;

/**
 *  When using some filters, namely the CSRFGuard filter, it will mess up character encoding (if using something else than US-ASCII).
 *  We use this filter to set the correct, configured in EJBCA, (i.e. UTF-8 to support intl characters) character encoding.
 *  
 *  We don't use a WebFilter annotation here, because we must set it in web.xml in order to enforce the order filters are called.
 *  
 * @version $Id$
*/
public class EncodingFilter implements Filter {

    private static final Logger log = Logger.getLogger(EncodingFilter.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException,IOException {
        log.trace("Using EncodingFilter to set HTTP request character encoding");
        try {
            RequestHelper.setDefaultCharacterEncoding((HttpServletRequest)request);
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
