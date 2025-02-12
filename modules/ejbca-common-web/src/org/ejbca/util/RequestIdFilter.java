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
import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

/**
 * <p>This filter is responsible for appending a unique Request ID to the application server's thread name.</p>
 * <p>The added Request ID is intended to ease tracing of all log messages related to individual incoming requests.</p>
 */
@WebFilter(filterName = "RequestIdFilter", urlPatterns = {"/*"})
public class RequestIdFilter implements Filter {

    private static final Logger log = Logger.getLogger(RequestIdFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final int randomInt = ThreadLocalRandom.current().nextInt(1000000, 10000000); // TODO delete me
        log.info("\uD83D\uDC40 RequestIdFilter filter hit. " + randomInt); // TODO delete me
        try (final RequestId requestId = new RequestId()) {
            log.info("\uD83D\uDC40 RequestId assigned. " + randomInt); // TODO delete me
            chain.doFilter(request, response);
        }
    }
}
