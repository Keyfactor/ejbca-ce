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
 
package org.ejbca.ui.web.admin.configuration;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Iterator;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * Servlet used to start services by calling the ServiceSession.load() at startup<br>
 *
 * 
 *
 * @version $Id: StartServicesServlet.java,v 1.14 2007-11-14 15:33:12 anatom Exp $
 * 
 * @web.servlet name = "StartServices"
 *              display-name = "StartServicesServlet"
 *              description="Servlet used to start services by calling the ServiceSession.load()"
 *              load-on-startup = "1"
 *
 * @web.servlet-mapping url-pattern = "/configuration/startservices"
 * 
 * @web.env-entry description="Determines if log4j should be initilized explicitly, needed for glassfish"
 *   name="LOG4JCONFIG"
 *   type="java.lang.String"
 *   value="${logging.log4j.config}"
 * 
 * @version $Id: StartServicesServlet.java,v 1.14 2007-11-14 15:33:12 anatom Exp $
 */
public class StartServicesServlet extends HttpServlet {

	private static final Logger log = Logger.getLogger(StartServicesServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /**
     * Method used to remove all active timers
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy() {
		String iMsg = intres.getLocalizedMessage("startservice.shutdown");
        log.info(iMsg);
        
        log.debug(">destroy calling ServiceSession.unload");
        try {
			getServiceHome().create().unload();
		} catch (Exception e) {
			log.error(e);
		}
		super.destroy();
	}


    private IServiceTimerSessionLocalHome servicehome = null;

    private synchronized IServiceTimerSessionLocalHome getServiceHome() throws IOException {
        try{
            if(servicehome == null){
            	servicehome = (IServiceTimerSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IServiceTimerSessionLocalHome.COMP_NAME);
            }
          } catch(Exception e){
              log.error("Error getting IServiceTimerSessionLocalHome: ", e);
              throw new java.io.IOException("Authorization Denied");
          }
          return servicehome;
    }
      

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
		String iMsg = intres.getLocalizedMessage("startservice.startup");
        log.info(iMsg);

        log.debug(">init calling ServiceSession.load");
        try {
			getServiceHome().create().load();
		} catch (Exception e) {
			log.error("Error init ServiceSession: ", e);
		}
		
        log.debug(">init initializing log4j");
        String configfile = ServiceLocator.getInstance().getString("java:comp/env/LOG4JCONFIG");
        if (!StringUtils.equals(configfile, "false")) {
            // Configure log4j
            if (StringUtils.equals(configfile, "basic")) {
                // Set up a simple configuration that logs on the console.
                BasicConfigurator.configure();            	
            } else {
            	System.setProperty("log4j.configuration", "file://"+configfile);
            }
        }

        // Reinstall BC-provider to help re-deploys to work
        log.debug("Re-installing BC-provider");
        CertTools.removeBCProvider();
        CertTools.installBCProvider();

        // Run java seed collector, that can take a little time the first time it is run
        log.debug(">init initializing random seed");
        SecureRandom rand = new SecureRandom();
        rand.nextInt();
        
        // Load CAs at startup to improve impression of speed the first time a CA is accessed, it takes a little time to load it.
        log.debug("init loading CAs into cache");
        try {
        	ICAAdminSessionLocalHome casessionhome = (ICAAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
        	ICAAdminSessionLocal casession;
        	casession = casessionhome.create();
        	Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "StartServicesServlet");
        	Collection caids = casession.getAvailableCAs(admin);
        	Iterator iter = caids.iterator();
        	while (iter.hasNext()) {
        		int caid = ((Integer)iter.next()).intValue();
        		CAInfo ca = casession.getCAInfo(admin, caid);
        		log.debug("Found CA: "+ca.getName()+", with expire time: "+ca.getExpireTime());
        	}
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }

    } // init

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        log.debug("<doGet()");
    } // doGet

}
