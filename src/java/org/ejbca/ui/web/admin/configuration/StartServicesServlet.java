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
import java.util.Properties;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
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
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.services.IServiceSessionLocal;
import org.ejbca.core.ejb.services.IServiceSessionLocalHome;
import org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.ProtectedLogDevice;
import org.ejbca.core.model.log.ProtectedLogExporter;
import org.ejbca.core.model.log.ProtectedLogVerifier;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.ProtectedLogExportWorker;
import org.ejbca.core.model.services.workers.ProtectedLogVerificationWorker;
import org.ejbca.util.CertTools;

/**
 * Servlet used to start services by calling the ServiceSession.load() at startup<br>
 *
 * 
 *
 * @version $Id$
 * 
 * @web.servlet name = "StartServices"
 *              display-name = "StartServicesServlet"
 *              description="Servlet used to start services by calling the ServiceSession.load()"
 *              load-on-startup = "1"
 *
 * @web.servlet-mapping url-pattern = "/configuration/startservices"
 * 
 * @web.env-entry description="Determines if log4j should be initialized explicitly, needed for glassfish, oracle"
 *   name="LOG4JCONFIG"
 *   type="java.lang.String"
 *   value="${logging.log4j.config}"
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

	private static final int MAX_SERVICE_WAIT = 30;
	
	private static final Logger log = Logger.getLogger(StartServicesServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    private IServiceSessionLocal serviceSession = null;
    private ILogSessionLocal logSession = null;
    
    /**
     * Method used to remove all active timers and stop system services.
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
        log.debug(">destroy waiting for system services to finish");
        ProtectedLogVerifier protectedLogVerifier = ProtectedLogVerifier.instance();
        if (protectedLogVerifier != null) {
        	protectedLogVerifier.cancelVerificationsPermanently();
        	long startedWaiting = System.currentTimeMillis();
        	log.info(intres.getLocalizedMessage("startservice.waitservicever", MAX_SERVICE_WAIT));
        	while (protectedLogVerifier.isRunning() && startedWaiting + MAX_SERVICE_WAIT*1000 > System.currentTimeMillis()) {
        		try {
					Thread.sleep(1*1000);
				} catch (InterruptedException e) {
					throw new EJBException(e);
				}
        	}
        }
        ProtectedLogExporter protectedLogExporter = ProtectedLogExporter.instance();
        if (protectedLogExporter != null) {
        	protectedLogExporter.cancelExportsPermanently();
        	long startedWaiting = System.currentTimeMillis();
        	log.info(intres.getLocalizedMessage("startservice.waitserviceexp", MAX_SERVICE_WAIT));
        	while (protectedLogExporter.isRunning() && startedWaiting + MAX_SERVICE_WAIT*1000 > System.currentTimeMillis()) {
        		try {
					Thread.sleep(1*1000);
				} catch (InterruptedException e) {
					throw new EJBException(e);
				}
        	}
        }
        ProtectedLogDevice protectedLogDevice = (ProtectedLogDevice) ProtectedLogDevice.instance();
        if (protectedLogDevice != null) {
        	protectedLogDevice.setSystemShutdownNotice();
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
      
    private synchronized IServiceSessionLocal getServiceSession() throws IOException {
        try{
            if(serviceSession == null){
            	serviceSession = ((IServiceSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IServiceSessionLocalHome.COMP_NAME)).create();
            }
          } catch(Exception e){
              throw new EJBException(e);
          }
          return serviceSession;
    }
    
	public ILogSessionLocal getLogSession(){
		if(logSession == null){
			try {
				logSession = ((ILogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ILogSessionLocalHome.COMP_NAME)).create();
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return logSession;
	}


    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        
        ejbcaInit();

    } // init

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");
        String param = req.getParameter("ejbcaInit");
        if (StringUtils.equals(param, "true")) {
        	ejbcaInit();
        } else {        
        	res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        }
        log.debug("<doGet()");
    } // doGet

    private void ejbcaInit() {
    	
        //
        // Run all "safe" initializations first, 
        // i.e. those that does not depend on other running beans, components etc
        //
        
        // Start with logging, so we are sure to know what is happening later on
        log.debug(">init initializing log4j");
        String configfile = ServiceLocator.getInstance().getString("java:comp/env/LOG4JCONFIG");
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
		String iMsg = intres.getLocalizedMessage("startservice.startup");
        log.info(iMsg);

        // Reinstall BC-provider to help re-deploys to work
        log.debug(">init re-installing BC-provider");
        CertTools.removeBCProvider();
        CertTools.installBCProvider();

        // Run java seed collector, that can take a little time the first time it is run
        log.debug(">init initializing random seed");
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

        Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
        getLogSession().log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null,
        		LogConstants.EVENT_INFO_STARTING, iMsg);

        log.debug(">init ProtectedLogVerificationService is configured");
        try {
        	Properties logProperties = getLogSession().getProperties(ProtectedLogDevice.class);
        	if (logProperties != null) {
        		if (logProperties.getProperty("verificationservice.active", "false").equalsIgnoreCase("true")) {
        			// Add or update service from configuration
        			ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
        			serviceConfiguration.setWorkerClassPath(ProtectedLogVerificationWorker.class.getName());
        			serviceConfiguration.setActionClassPath(NoAction.class.getName());
        			Properties intervalProperties = new Properties();
        			intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_MINUTES);
        			intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, logProperties.getProperty(ProtectedLogVerificationWorker.CONF_VERIFICATION_INTERVAL,
        					ProtectedLogVerificationWorker.DEFAULT_VERIFICATION_INTERVAL));
        			serviceConfiguration.setIntervalProperties(intervalProperties);
        			serviceConfiguration.setIntervalClassPath(PeriodicalInterval.class.getName());
        			serviceConfiguration.setActive(true);
        			serviceConfiguration.setHidden(true);
        			serviceConfiguration.setWorkerProperties(logProperties);
        			if (getServiceSession().getService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME) != null) {
        				getServiceSession().changeService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME, serviceConfiguration);
        			} else {
        				getServiceSession().addService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME, serviceConfiguration);
        			}
        		} else {
        			// Remove if existing
        			if (getServiceSession().getService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME) != null) {
        				getServiceSession().removeService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME);
        			}
        		}
        	}
		} catch (ServiceExistsException e) {
			throw new EJBException(e);
		} catch (IOException e) {
			log.error("Error init ServiceSession: ", e);
		}

        log.debug(">init ProtectedLogExportService is configured");
        try {
        	Properties logProperties = getLogSession().getProperties(ProtectedLogDevice.class);
        	if (logProperties != null) {
        		if (logProperties.getProperty("exportservice.active", "false").equalsIgnoreCase("true")) {
        			// Add or update service from configuration
        			ServiceConfiguration serviceConfiguration = new ServiceConfiguration();
        			serviceConfiguration.setWorkerClassPath(ProtectedLogExportWorker.class.getName());
        			serviceConfiguration.setActionClassPath(NoAction.class.getName());
        			Properties intervalProperties = new Properties();
        			intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_MINUTES);
        			intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, logProperties.getProperty(ProtectedLogExportWorker.CONF_EXPORT_INTERVAL,
        					ProtectedLogExportWorker.DEFAULT_EXPORT_INTERVAL));
        			serviceConfiguration.setIntervalProperties(intervalProperties);
        			serviceConfiguration.setIntervalClassPath(PeriodicalInterval.class.getName());
        			serviceConfiguration.setActive(true);
        			serviceConfiguration.setHidden(true);
        			serviceConfiguration.setWorkerProperties(logProperties);
        			if (getServiceSession().getService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME) != null) {
        				getServiceSession().changeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration);
        			} else {
        				getServiceSession().addService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration);
        			}
        		} else {
        			// Remove if existing
        			if (getServiceSession().getService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME) != null) {
        				getServiceSession().removeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME);
        			}
        		}
        	}
		} catch (ServiceExistsException e) {
			throw new EJBException(e);
		} catch (IOException e) {
			log.error("Error init ServiceSession: ", e);
		}

        log.debug(">init calling ServiceSession.load");
        try {
			getServiceHome().create().load();
		} catch (Exception e) {
			log.error("Error init ServiceSession: ", e);
		}
		
		log.debug(">init CATokenManager");
		CATokenManager.instance();
		
        // Load CAs at startup to improve impression of speed the first time a CA is accessed, it takes a little time to load it.
        log.debug(">init loading CAs into cache");
        try {
        	ICAAdminSessionLocalHome casessionhome = (ICAAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
        	ICAAdminSessionLocal casession;
        	casession = casessionhome.create();
        	Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "StartServicesServlet");
        	casession.initializeAndUpgradeCAs(admin);
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }
    }
    
}
