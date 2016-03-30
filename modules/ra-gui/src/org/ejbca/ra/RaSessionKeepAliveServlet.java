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
package org.ejbca.ra;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;

/**
 * Servlet for receiving AJAX requests that keeps the HTTP session alive.
 * 
 * @version $Id$
 */
@WebServlet("/sessionKeepAlive")
public class RaSessionKeepAliveServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaSessionKeepAliveServlet.class);
    
    private static final int MAX_INACTIVE_INTERVAL_JSCLIENT_SECONDS = 60;

    @Override
    protected void service(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws ServletException, IOException {
        if (httpServletRequest.getRequestedSessionId()==null || !httpServletRequest.isRequestedSessionIdValid()) {
            // No session, so nothing to keep alive...
            httpServletResponse.sendError(500);
            return;
        }
        // Calling httpServletRequest.getSession() will re-validate the session
        final HttpSession httpSession = httpServletRequest.getSession();
        // Get and save the original web.xml session-timeout
        int maxInactiveIntervalSeconds = httpSession.getMaxInactiveInterval();
        if (maxInactiveIntervalSeconds>MAX_INACTIVE_INTERVAL_JSCLIENT_SECONDS) {
            // Since the client has JavaScript enabled (pretty safe to assume since this is accessed via AJAX), we can set the session timeout more aggressively
            maxInactiveIntervalSeconds = MAX_INACTIVE_INTERVAL_JSCLIENT_SECONDS;
            httpSession.setMaxInactiveInterval(maxInactiveIntervalSeconds);
            if (log.isDebugEnabled()) {
                log.debug("Client with jsessionid=" + httpSession.getId() + " called keep alive servlet. Adjusted MaxInactiveInterval to " + maxInactiveIntervalSeconds);
            }
        }
        // Use a fail safe of 10000 milliseconds when calculating the time to the next check
        final int timeToNextCheckInMs = Math.max(10000, (maxInactiveIntervalSeconds-10)*1000);
        if (log.isDebugEnabled()) {
            log.debug("maxInactiveIntervalSeconds: " + maxInactiveIntervalSeconds + " jsessionid=" + httpSession.getId());
        }
        httpServletResponse.setContentType("text/plain");
        httpServletResponse.getWriter().write(String.valueOf(timeToNextCheckInMs));
    }
}
