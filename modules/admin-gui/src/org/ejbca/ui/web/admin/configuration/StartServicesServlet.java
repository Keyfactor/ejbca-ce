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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.UserTransaction;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.dbprotection.ProtectedDataConfiguration;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Servlet used to start services by calling the ServiceSession.load() at startup<br>
 * 
 * @version $Id$
 */
public class StartServicesServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(StartServicesServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private ServiceSessionLocal serviceSession;
    @EJB
    private CertificateCreateSessionLocal certCreateSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private ComplexAccessControlSessionLocal complexAccessControlSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    
    @Resource
    private UserTransaction tx;
    
    /**
     * Method used to log service shutdown.
	 * @see javax.servlet.GenericServlet#destroy()
	 **/
    @Override
	public void destroy() {
        String iMsg = intres.getLocalizedMessage("startservice.shutdown");
        log.info(iMsg);

        // Making an EJB call to audit log shutdown is not possible, since the EJBs will shut down before the servlet. 
        // This should be possible to handle  with EJB 3.1
        /*
        @Singleton
        @Startup
        public class StartupBean {

        @PostConstruct
        private void startup() { ... }

        @PreDestroy
        private void shutdown() { ... }
        ...
        }
        */
        // Make a log row that EJBCA is stopping
//        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("StartServicesServlet.destroy"));
//        final Map<String, Object> details = new LinkedHashMap<String, Object>();
//        details.put("msg", iMsg);
//        logSession.log(EjbcaEventTypes.EJBCA_STOPPING, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);                

        super.destroy();
	}

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ejbcaInit();
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    } //doPost

    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");
    	res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Servlet doesn't support requests is only loaded on startup.");
        log.trace("<doGet()");
    } // doGet

    private void ejbcaInit() {
    	
        //
        // Run all "safe" initializations first, 
        // i.e. those that does not depend on other running beans, components etc

        
        // Log a startup message
		String iMsg = intres.getLocalizedMessage("startservice.startup", GlobalConfiguration.EJBCA_VERSION);
        log.info(iMsg);

        // Reinstall BC-provider to help re-deploys to work
        log.trace(">init re-installing BC-provider");
        CryptoProviderTools.removeBCProvider();
        CryptoProviderTools.installBCProvider();

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
        
		log.trace(">init CryptoTokenFactory just to load those classes that are available");
		CryptoTokenFactory.instance();
		
        // Load CAs at startup to improve impression of speed the first time a CA is accessed, it takes a little time to load it.
        log.trace(">init loading CAs into cache");
        try {
        	caAdminSession.initializeAndUpgradeCAs();
        } catch (Exception e) {
        	log.error("Error creating CAAdminSession: ", e);
        }

    	AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("StartServicesServlet.init"));

        // Make a log row that EJBCA is starting
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", iMsg);
        logSession.log(EjbcaEventTypes.EJBCA_STARTING, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);				

        // Log the type of security audit configuration that we have enabled.
        log.trace(">init security audit device configuration");
        // See if we have IntegrityProtectedDevice configured, due to class loading constraints we can not use IntegrityProtectedDevice.class.getSimpleName().
        // This is admin-gui and does not have access to that class
        final String integrityProtectedName = "IntegrityProtectedDevice";
        final String auditTableName = AuditRecordData.class.getSimpleName();
        final Set<String> loggerIds = AuditDevicesConfig.getAllDeviceIds();
        if (loggerIds.isEmpty()) {
            final String msg = intres.getLocalizedMessage("startservices.noauditdevices");
            log.info(msg);
        }
        boolean haveSecurityAudit = false;
        for (Iterator<String> iterator = loggerIds.iterator(); iterator.hasNext();) {
            final String id = (String) iterator.next();
            if (integrityProtectedName.equals(id)) {
                // Make a log row that integrity protected device is configured
                final Map<String, Object> logdetails = new LinkedHashMap<String, Object>();
                final Integer keyid = ProtectedDataConfiguration.instance().getKeyId(auditTableName);
                if ((keyid != null) && (keyid > 0)) {
                    if (ProtectedDataConfiguration.useDatabaseIntegrityProtection(auditTableName)) {
                        logdetails.put("keyid", keyid);
                        logdetails.put("protectVersion", ProtectedDataConfiguration.instance().getProtectVersion(keyid));
                        logdetails.put("keyLabel", ProtectedDataConfiguration.instance().getKeyLabel(keyid));
                        logSession.log(EventTypes.LOG_MANAGEMENT_CHANGE, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, admin.toString(), null, null, null, logdetails);
                        haveSecurityAudit = true;                                            
                    } else {
                        log.debug("No database integrity protection enabled for AuditRecordData.");
                    }
                } else {
                    log.debug("No keyid configured for AuditRecordData.");
                }
            }
        }
        if (!haveSecurityAudit) {
            // Make a log row that no integrity protected device is configured
            final String msg = intres.getLocalizedMessage("startservices.noprotectedauditdevices");
            final Map<String, Object> logdetails = new LinkedHashMap<String, Object>();
            logdetails.put("msg", msg);
            logSession.log(EventTypes.LOG_MANAGEMENT_CHANGE, EventStatus.VOID, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, admin.toString(), null, null, null, logdetails);                
        }

        // Initialize authorization system, if not done already
        log.trace(">init ComplexAccessControlSession to check for initial root role");
        complexAccessControlSession.initializeAuthorizationModule();

        log.trace(">init calling ServiceSession.load");
        try {
        	serviceSession.load();
		} catch (Exception e) {
			log.error("Error init ServiceSession: ", e);
		}
		
        // Load Certificate profiles at startup to upgrade them if needed
        log.trace(">init loading CertificateProfile to check for upgrades");
        try {
        	certificateProfileSession.initializeAndUpgradeProfiles();
        } catch (Exception e) {
        	log.error("Error initializing certificate profiles: ", e);
        }
        
        // Load EndEntity profiles at startup to upgrade them if needed
        // And add this node to list of nodes
        log.trace(">init loading EndEntityProfile to check for upgrades");
        try {
        	endEntityProfileSession.initializeAndUpgradeProfiles();        	
        } catch (Exception e) {
        	log.error("Error initializing end entity profiles: ", e);
        }
        
        // Add this node's hostname to list of nodes
        log.trace(">init checking if this node is in the list of nodes");
        try {
            // Requires a transaction in order to create the initial global configuration
            tx.begin();
            try {
                final GlobalConfiguration config = globalConfigurationSession.getCachedGlobalConfiguration();
                final Set<String> nodes = config.getNodesInCluster();
                final String hostname = getHostName();
                if (hostname != null && !nodes.contains(hostname)) {
                    log.debug("Adding this node the list of nodes");
                    nodes.add(hostname);
                    config.setNodesInCluster(nodes);
                    globalConfigurationSession.saveGlobalConfiguration(admin, config);
                }
            } finally {
                tx.commit();
            }
        } catch (Exception e) {
            log.error("Error adding host to node list in global configuration: ", e);
        } 

        log.trace(">init SignSession to check for unique issuerDN,serialNumber index");
        // Call the check for unique index, since first invocation will perform the database
        // operation and avoid a performance hit for the first request where this is checked.
        certCreateSession.isUniqueCertificateSerialNumberIndex();       
        
        /*
         * FIXME: This is a hack, because we need some sort of annotation or service loader to make sure 
         * that the AccessMatchValue-implementing enums get initialized at runtime. Sadly, enums aren't 
         * initialized until they're called, which causes trouble with this registry. 
         * 
         * These lines are to be removed once a dynamic initialization heuristic has been developed.
         * 
         */      
        try {
            Class.forName(X500PrincipalAccessMatchValue.class.getName());
            Class.forName(CliUserAccessMatchValue.class.getName());
        } catch (ClassNotFoundException e) {
            log.error("Failure during match value initialization", e);
        }
        // Check and upgrade if this is the first time we start an instance that was previously an stand-alone VA
        ocspResponseGeneratorSession.adhocUpgradeFromPre60(null);
        // Start key reload timer
        ocspResponseGeneratorSession.initTimers();
        
        cryptoTokenManagementSession.adhocUpgradeWithin6_0_x(admin);
    }
    
    /**
     * @return The host's name or null if it could not be determined.
     */
    private String getHostName() {
    	String hostname = null;
    	try {
	        InetAddress addr = InetAddress.getLocalHost();    
	        // Get hostname
	        hostname = addr.getHostName();
	    } catch (UnknownHostException e) {
	    	log.error("Hostname could not be determined", e);
	    }
	    return hostname;
    }
    
}
