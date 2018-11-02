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
package org.ejbca.ui.web.admin;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.config.InternalConfiguration;
import org.ejbca.config.WebConfiguration;

/**
 * Servlet for invalidation of the current HTTP session.
 * 
 * @version $Id$
 */
public class LogOutServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    // JavaServlet Specification 2.5 Section 7.1.1: "...The name of the session tracking cookie must be JSESSIONID".
    private static final String SESSIONCOOKIENAME = "JSESSIONID";

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
    	doGet(request, response);
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
    	// First we invalidate the current session on the server side, so the old session cookie cannot be used again.
        request.getSession().invalidate();
        // Next, we ask the browser to remove the cookie (a sneaky client can refuse to comply)
        final Cookie killCookie = new Cookie(SESSIONCOOKIENAME, "");
        killCookie.setMaxAge(0);
        killCookie.setPath(request.getContextPath());
        // JsessionID cookies that we can logout are always secure, and we only login over https, so do the same for logout
        killCookie.setHttpOnly(true);
        killCookie.setSecure(true);
        response.addCookie(killCookie);
        if (WebConfiguration.isProxiedAuthenticationEnabled()) {
        	// Redirect user to "/logout" that can be handled by a authentication proxy
            response.sendRedirect("/logout");
        } else {
        	// Redirect user to the public web pages to avoid initializing a new AdminGUI session.
            response.sendRedirect("/" + InternalConfiguration.getAppNameLower() + "/");
        }
    }
}
