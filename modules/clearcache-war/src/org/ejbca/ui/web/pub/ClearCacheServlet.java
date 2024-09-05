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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import jakarta.ejb.EJB;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.config.ClearCacheSessionLocal;

/**
 * Servlet used to clear all caches (Global Configuration Cache, End Entity Profile Cache, 
 * Certificate Profile Cache, Log Configuration Cache, Authorization Cache and CA Cache).
 *
 * @version $Id$
 */
public class ClearCacheServlet extends HttpServlet {

	private static final long serialVersionUID = -8563174167843989458L;
	private static final Logger log = Logger.getLogger(ClearCacheServlet.class);
	
	private static final Set<String> LOCALHOST_IPS = new HashSet<>(Arrays.asList("127.0.0.1", "0:0:0:0:0:0:0:1", "::1"));
	
    @EJB
    private ClearCacheSessionLocal clearCacheSession;
    @EJB
    private GlobalConfigurationSessionLocal globalconfigurationsession;

    public void doPost(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse)	throws IOException, ServletException {
    	doGet(httpServletRequest,httpServletResponse);
    }

    public void doGet(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse) throws IOException, ServletException {
        if (log.isTraceEnabled()) {
            log.trace(">doGet()");
        }
        if (StringUtils.equals(httpServletRequest.getParameter("command"), "clearcaches")) {
            final boolean excludeActiveCryptoTokens = StringUtils.equalsIgnoreCase("true", httpServletRequest.getParameter("excludeactivects"));
            if (isLocalhostAddress(httpServletRequest.getRemoteAddr()) || acceptedHost(httpServletRequest.getRemoteHost())) {
                clearCacheSession.clearCaches(excludeActiveCryptoTokens);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Clear cache request denied from host "+httpServletRequest.getRemoteHost());
                }
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The remote host "+httpServletRequest.getRemoteHost()+" is unknown");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("No clearcaches command (?command=clearcaches) received, returning bad request.");
            }
            httpServletResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "No command.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<doGet()");
        }
    }
	
	/** @return true if the provided IP address matches one of commonly knwon localhost IP addresses */
	private boolean isLocalhostAddress(final String remoteAddress) {
        if (log.isTraceEnabled()) {
            log.trace(">isAcceptedAddress: "+remoteAddress);
        }
        if (remoteAddress!=null && LOCALHOST_IPS.contains(remoteAddress)) {
            // Always allow requests from localhost, 127.0.0.1 may not be added in the list
            if (log.isDebugEnabled()) {
                log.debug("Always allowing request from '" + remoteAddress + "'");
            }
            return true;
        }
	    return false;
	}

	private boolean acceptedHost(String remotehost) {
		if (log.isTraceEnabled()) {
			log.trace(">acceptedHost: "+remotehost);
		}    	
		boolean ret = false;
		final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalconfigurationsession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
		for (final String nodename : globalConfiguration.getNodesInCluster()) {
			try {
			    // Perform reverse DNS lookup.
			    // (In a DDoS scenario, a performance assumption is that these lookups are cached by a local resolver or similar or that this URL path is shielded from hostile networks..)
				String nodeip = InetAddress.getByName(nodename).getHostAddress();
				if (log.isDebugEnabled()) {
					log.debug("Checking remote host against host in list: "+nodename+", "+nodeip);
				}
				// Assume that automatic reverse DNS lookup is disabled in the Servlet container and compare "remotehost" with the IP address we got
				if (StringUtils.equals(remotehost, nodeip)) {
					ret = true;
					break;
				}
			} catch (UnknownHostException e) {
				if (log.isDebugEnabled()) {
					log.debug("Unknown host '"+nodename+"': "+e.getMessage());
				}
			}
		}
		if (log.isTraceEnabled()) {
			log.trace("<acceptedHost: "+ret);
		}
		return ret;
	}
}
