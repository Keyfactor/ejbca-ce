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

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.xml.DOMConfigurator;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.CertTools;

/**
 * Servlet used to start services by calling the ServiceSession.load() at startup<br>
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final int MAX_SERVICE_WAIT = 30;
	private static final Logger log = Logger.getLogger(StartServicesServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private RaAdminSessionLocal raAdminSession;
    @EJB
    private ServiceSessionLocal serviceSession;
    
    /**
     * Method used to remove all active timers and stop system services.
	 * @see javax.servlet.GenericServlet#destroy()
	 */
	public void destroy() {
		String iMsg = intres.getLocalizedMessage("startservice.shutdown");
        log.info(iMsg);
        
        log.trace(">destroy calling ServiceSession.unload");
        try {
			serviceSession.unload();
		} catch (Exception e) {
			log.error(e);
		}
        log.trace(">destroy waiting for system services to finish");
		super.destroy();
	}

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    	if (caAdminSession==null || certificateStoreSession==null || logSession==null || raAdminSession==null || serviceSession==null) {
    		log.error("Local EJB injection failed.");
    	}
        ejbcaInit();
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");
        String param = req.getParameter("ejbcaInit");
        if (StringUtils.equals(param, "true")) {
        	ejbcaInit();
        } else {        
        	res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        }
        log.trace("<doGet()");
    } // doGet

    private void ejbcaInit() {
    	
        //
        // Run all "safe" initializations first, 
        // i.e. those that does not depend on other running beans, components etc
        //
        
        // Start with logging, so we are sure to know what is happening later on
        log.trace(">init initializing log4j");
        String configfile = EjbcaConfiguration.getLoggingLog4jConfig();
        if (!StringUtils.equals(configfile, "false")) {
            // Configure log4j
            if (StringUtils.equals(configfile, "basic")) {
                // Set up a simple configuration that logs on the console.
                BasicConfigurator.configure();            	
            } else {
            	System.setProperty("log4j.configuration", "file://"+configfile);
            	File f = new File(configfile);
            	URL url;
				try {
					url = f.toURL();
	            	if (StringUtils.contains(configfile, ".properties")) {
	                	PropertyConfigurator.configure(url);     
	                	log.debug("Configured log4j with PropertyConfigurator: "+url);
	            	} else if (StringUtils.contains(configfile, ".xml")) {
	            		DOMConfigurator.configure(url);
	                	log.debug("Configured log4j with DOMConfigurator: "+url);
	            	}
				} catch (MalformedURLException e) {
					log.error("Can not configure log4j: ", e);
					e.printStackTrace();
				}
            }
        }
        
        // Log a startup message
		String iMsg = intres.getLocalizedMessage("startservice.startup", GlobalConfiguration.EJBCA_VERSION);
        log.info(iMsg);

        // Reinstall BC-provider to help re-deploys to work
        log.trace(">init re-installing BC-provider");
        CertTools.removeBCProvider();
        CertTools.installBCProvider();

        // Run java seed collector, that can take a little time the first time it is run
        log.trace(">init initializing random seed");
        SecureRandom rand = new SecureRandom();
        rand.nextInt();
        
        //
        // Start services that requires calling other beans or components
        //
        
        // We really need BC to be installed. This is an attempt to fix a bug where the ServiceSessionBean
        // crashes from not finding the BC-provider.
        int waitTime = 0;
        while (Security.getProvider("BC") == null && waitTime++ < 5) {
        	log.info("Waiting for BC provider to be installed..");
        	try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				log("Waiting for BC provider failed.", e);
				break;
			}
        }

        // We have to read CAs into cache (and upgrade them) early, because the log system may use CAs for signing logs
        
		log.trace(">init CATokenManager");
		CATokenManager.instance();
		
        // Load CAs at startup to improve impression of speed the first time a CA is accessed, it takes a little time to load it.
        log.trace(">init loading CAs into cache");
        try {
        	Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "StartServicesServlet");
        	caAdminSession.initializeAndUpgradeCAs(admin);
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }

        // Make a log row that EJBCA is starting
        Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null,
        		LogConstants.EVENT_INFO_STARTING, iMsg);

        log.trace(">init calling ServiceSession.load");
        try {
        	serviceSession.load();
		} catch (Exception e) {
			log.error("Error init ServiceSession: ", e);
		}
		
        // Load Certificate profiles at startup to upgrade them if needed
        log.trace(">init loading CertificateProfile to check for upgrades");
        try {
        	Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "StartServicesServlet");
        	certificateStoreSession.initializeAndUpgradeProfiles(admin);
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }
        
        // Load EndEntity profiles at startup to upgrade them if needed
        log.trace(">init loading EndEntityProfile to check for upgrades");
        try {
        	Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "StartServicesServlet");
        	raAdminSession.initializeAndUpgradeProfiles(admin);
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }
    }
    
}
