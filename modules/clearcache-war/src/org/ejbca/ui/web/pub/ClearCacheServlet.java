/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.Iterator;
import java.util.Set;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;

/**
 * Servlet used to clear all caches (Global Configuration Cache, End Entity Profile Cache, 
 * Certificate Profile Cache, Log Configuration Cache, Authorization Cache and CA Cache).
 *
 * @author Aveen Ismail
 * 
 * @version $Id$
 */
public class ClearCacheServlet extends HttpServlet {

	private static final long serialVersionUID = -8563174167843989458L;
	private static final Logger log = Logger.getLogger(ClearCacheServlet.class);
	
	@EJB
	private AccessControlSessionLocal accessControlSession;
	@EJB
	private GlobalConfigurationSessionLocal globalconfigurationsession;
	@EJB
	private EndEntityProfileSessionLocal endentitysession;
	@EJB
	private CertificateProfileSessionLocal certificateprofilesession;
	@EJB
	private CaSessionLocal casession;
	
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }
  
    public void doPost(HttpServletRequest req, HttpServletResponse res)	throws IOException, ServletException {
    	doGet(req,res);
    }


	public void doGet(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
		if (log.isTraceEnabled()) {
			log.trace(">doGet()");
		}
        
        if (StringUtils.equals(req.getParameter("command"), "clearcaches")) {
            if(!acceptedHost(req.getRemoteHost())) {
        		if (log.isDebugEnabled()) {
        			log.debug("Clear cache request denied from host "+req.getRemoteHost());
        		}
        		res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "The remote host "+req.getRemoteHost()+" is unknown");
        	} else {       
        		globalconfigurationsession.flushGlobalConfigurationCache();
        		if(log.isDebugEnabled()){
        			log.debug("Global Configuration cache cleared");
        		}
        			
        		endentitysession.flushProfileCache();
        		if(log.isDebugEnabled()) {
        			log.debug("RA Profile cache cleared");
        		}
        		
        		certificateprofilesession.flushProfileCache();
        		if(log.isDebugEnabled()) {
        			log.debug("Cert Profile cache cleared");
        		}
        		accessControlSession.forceCacheExpire();
        		if(log.isDebugEnabled()) {
        			log.debug("Authorization Rule cache cleared");
        		}
			
        		casession.flushCACache();
        		if(log.isDebugEnabled()) {
        			log.debug("CA cache cleared");
        		}
        	}
        } else {
    		if (log.isDebugEnabled()) {
    			log.debug("No clearcaches command (?command=clearcaches) received, returning bad request.");
    		}
			res.sendError(HttpServletResponse.SC_BAD_REQUEST, "No command.");
        }
		if (log.isTraceEnabled()) {
			log.trace("<doGet()");
		}
    }

	private boolean acceptedHost(String remotehost) {
		if (log.isTraceEnabled()) {
			log.trace(">acceptedHost: "+remotehost);
		}    	
		boolean ret = false;
		GlobalConfiguration gc = globalconfigurationsession.getCachedGlobalConfiguration();
		Set<String> nodes = gc.getNodesInCluster();
		Iterator<String> itr = nodes.iterator();
		String nodename = null;
		while (itr.hasNext()) {
			nodename = itr.next();
			try {
				String nodeip = InetAddress.getByName(nodename).getHostAddress();
				if (log.isDebugEnabled()) {
					log.debug("Checking remote host against host in list: "+nodename+", "+nodeip);
				}
				if (StringUtils.equals(remotehost, nodeip)) {
					ret = true;
				} else if (StringUtils.equals(remotehost, "127.0.0.1")) {
					// Always allow requests from localhost, 127.0.0.1 may not be added in the list
					if (log.isDebugEnabled()) {
						log.debug("Always allowing request from 127.0.0.1");
					}
					ret = true;
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
