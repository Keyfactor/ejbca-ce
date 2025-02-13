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

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;

import java.io.IOException;

/**
 * <p>This filter is responsible for appending a unique Request ID to the application server's thread name.</p>
 * <p>The added Request ID is intended to ease tracing of all log messages related to individual incoming requests.</p>
 */
@WebFilter(filterName = "RequestIdFilter", urlPatterns = {"/*"})
public class RequestIdFilter implements Filter {

    @Override
    @SuppressWarnings("unused")
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        try (final RequestId requestId = new RequestId()) {
            chain.doFilter(request, response);
        }
    }
}
