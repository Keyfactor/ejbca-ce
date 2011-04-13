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

package org.ejbca.core.ejb.services;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.crl.CrlCreateSessionLocal;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CaSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExistsException;

/**
 * Session bean that handles adding and editing services as displayed in EJBCA. 
 * This bean manages the service configuration as stored in the database, but is not used for running the services. 
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ServiceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceSessionBean implements ServiceSessionLocal, ServiceSessionRemote {

    private static final Logger log = Logger.getLogger(ServiceSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Constant indicating the Id of the "service loader" service. Used in a
     * clustered environment to periodically load available services
     */
    private static final Integer SERVICELOADER_ID = 0;

    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

    @Resource
    private SessionContext sessionContext;
    private TimerService timerService;	// When the sessionContext is injected, the timerService should be looked up.
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private ServiceDataSessionLocal serviceDataSession;
    private ServiceSessionLocal serviceSession;

    // Additional dependencies from the services we executeServiceInTransaction
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private AuthenticationSessionLocal authenticationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlCreateSessionLocal crlCreateSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private RaAdminSessionLocal raAdminSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    
    private Admin intAdmin = Admin.getInternalAdmin();	// The administrator that the services should be run as.

    @PostConstruct
    public void ejbCreate() {
    	timerService = sessionContext.getTimerService();
    	serviceSession = sessionContext.getBusinessObject(ServiceSessionLocal.class);
    }
        			
    @Override
    public void addService(Admin admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ")");
        }
        addService(admin, findFreeServiceId().intValue(), name, serviceConfiguration);
        log.trace("<addService()");
    }

    @Override
    public void addService(Admin admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ", id: " + id + ")");
        }
        boolean success = false;
        if (isAuthorizedToEditService(admin, serviceConfiguration)) {
            if (serviceDataSession.findByName(name) == null) {
                if (serviceDataSession.findById(Integer.valueOf(id)) == null) {
                    try {
                        serviceDataSession.addServiceData(id, name, serviceConfiguration);
                        success = true;
                    } catch (Exception e) {
                        log.error("Unexpected error creating new service: ", e);
                    }
                }
            }
            if (success) {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED,
                        intres.getLocalizedMessage("services.serviceadded", name));
            } else {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED,
                        intres.getLocalizedMessage("services.erroraddingservice", name));
                throw new ServiceExistsException();
            }
        } else {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    intres.getLocalizedMessage("services.notauthorizedtoadd", name));
        }
        log.trace("<addService()");
    }

    @Override
    public void cloneService(Admin admin, String oldname, String newname) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">cloneService(name: " + oldname + ")");
        }
        ServiceConfiguration servicedata = null;
        ServiceData htp = serviceDataSession.findByName(oldname);
        if (htp == null) {
            String msg = "Error cloning service: No such service found.";
            log.error(msg);
            throw new EJBException(msg);
        }
        try {
            servicedata = (ServiceConfiguration) htp.getServiceConfiguration().clone();
            if (isAuthorizedToEditService(admin, servicedata)) {
                try {
                    addService(admin, newname, servicedata);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                            LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicecloned", newname, oldname));
                } catch (ServiceExistsException f) {
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                            LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorcloningservice", newname, oldname));
                    throw f;
                }
            } else {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                        intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
            }
        } catch (CloneNotSupportedException e) {
            log.error("Error cloning service: ", e);
            throw new EJBException(e);
        }
        log.trace("<cloneService()");
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean removeService(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">removeService(name: " + name + ")");
        }
        boolean retval = false;
        try {
            ServiceData htp = serviceDataSession.findByName(name);
            if (htp == null) {
                throw new FinderException("Cannot find service " + name);
            }
            ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
            if (isAuthorizedToEditService(admin, serviceConfiguration)) {
                IWorker worker = getWorker(serviceConfiguration, name, htp.getRunTimeStamp(), htp.getNextRunTimeStamp());
                if (worker != null) {
                    serviceSession.cancelTimer(htp.getId());
                }
                serviceDataSession.removeServiceData(htp.getId());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceremoved", name));
                retval = true;
            } else {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null,
                        LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", name));
            }
        } catch (Exception e) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorremovingservice", name), e);
        }
        log.trace("<removeService)");
        return retval;
    }

    @Override
    public void renameService(Admin admin, String oldname, String newname) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renameService(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        if (serviceDataSession.findByName(newname) == null) {
            ServiceData htp = serviceDataSession.findByName(oldname);
            if (htp != null) {
                if (isAuthorizedToEditService(admin, htp.getServiceConfiguration())) {
                    htp.setName(newname);
                    success = true;
                } else {
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null,
                            LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
                }
            }
        }
        if (success) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED,
                    intres.getLocalizedMessage("services.servicerenamed", oldname, newname));
        } else {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED,
                    intres.getLocalizedMessage("services.errorrenamingservice", oldname, newname));
            throw new ServiceExistsException();
        }
        log.trace("<renameService()");
    }

    @Override
    public Collection<Integer> getAuthorizedVisibleServiceIds(Admin admin) {
        Collection<Integer> allVisibleServiceIds = new ArrayList<Integer>();
        // If superadmin return all visible services
        if(authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            Collection<Integer> allServiceIds = getServiceIdToNameMap(admin).keySet();
            Iterator<Integer> i = allServiceIds.iterator();
            while (i.hasNext()) {
                int id = i.next().intValue();
                // Remove hidden services here..
                if (!getServiceConfiguration(admin, id).isHidden()) {
                    allVisibleServiceIds.add(Integer.valueOf(id));
                }
            }
        } else {
            log.debug("Authorization denied for admin " + admin.getUsername() + " for resouce " + AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        }
        return allVisibleServiceIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ServiceConfiguration getService(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">getService: " + name);
        }
        ServiceConfiguration returnval = null;
        ServiceData serviceData = serviceDataSession.findByName(name);
        if (serviceData != null) {
            returnval = serviceData.getServiceConfiguration();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getService: " + name);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getServiceId(Admin admin, String name) {
        int returnval = 0;
        ServiceData serviceData = serviceDataSession.findByName(name);
        if (serviceData != null) {
            returnval = serviceData.getId();
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void activateServiceTimer(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">activateServiceTimer(name: " + name + ")");
        }
        ServiceData htp = serviceDataSession.findByName(name);
        if (htp != null) {
            ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
            if (isAuthorizedToEditService(admin, serviceConfiguration)) {
                IWorker worker = getWorker(serviceConfiguration, name, htp.getRunTimeStamp(), htp.getNextRunTimeStamp());
                if (worker != null) {
                    serviceSession.cancelTimer(htp.getId());
                    if (serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
                        addTimer(worker.getNextInterval() * 1000, htp.getId());
                    }
                }
            } else {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                        intres.getLocalizedMessage("services.notauthorizedtoedit", name));
            }
        } else {
            log.error("Can not find service: " + name);
        }
        log.trace("<activateServiceTimer()");
    }
    
    private Integer findFreeServiceId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
            if (id > 1) {
                if (serviceDataSession.findById(Integer.valueOf(id)) == null) {
                    foundfree = true;
                }
            }
            id = ran.nextInt();
        }
        return  id;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getServiceName(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getServiceName(id: " + id + ")");
        }
        String returnval = null;
        ServiceData serviceData = serviceDataSession.findById(id);
        if (serviceData != null) {
            returnval = serviceData.getName();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getServiceName()");
        }
        return returnval;
    }
    
    /**
     * Method implemented from the TimerObject and is the main method of this
     * session bean. It calls the work object for each object.
     * 
     * @param timer timer whose expiration caused this notification.
     */
    @Timeout
    // Glassfish 2.1.1: "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
    // JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">ejbTimeout");
        }
        final long startOfTimeOut = new Date().getTime();
    	long serviceInterval = IInterval.DONT_EXECUTE;
        Integer timerInfo = (Integer) timer.getInfo();
        if (timerInfo.equals(SERVICELOADER_ID)) {
            if (log.isDebugEnabled()) {
                log.debug("Running the internal Service loader.");
            }
            load();
        } else {
        	String serviceName = null;
        	try {
        		serviceName = serviceDataSession.findNameById(timerInfo);
        	} catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception: ", t);	// Don't spam log with stacktraces in normal production cases
                }
                // Unexpected error (probably database related). We need to reschedule the service w a default interval..
                addTimer(30 * 1000, timerInfo);
        	}
        	if (serviceName == null) {
                logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicenotfound", timerInfo));
        	} else {
            	// Get interval of worker
            	try {
            		serviceInterval = serviceSession.getServiceInterval(timerInfo);
            	} catch (Throwable t) {
                    if (log.isDebugEnabled()) {
                        log.debug("Exception: ", t);	// Don't spam log with stacktraces in normal production cases
                    }
                    // Unexpected error (probably database related). We need to reschedule the service w a default interval..
                    addTimer(30 * 1000, timerInfo);
            	}
            	// Reschedule timer
                IWorker worker = null;
            	if (serviceInterval != IInterval.DONT_EXECUTE) {
                	Timer nextTrigger = addTimer(serviceInterval * 1000, timerInfo);
                	try {
                    	// Try to acquire lock / see if this node should run
                    	worker = serviceSession.getWorkerIfItShouldRun(timerInfo, nextTrigger.getNextTimeout().getTime());
                	} catch (Throwable t) {
                        if (log.isDebugEnabled()) {
                            log.debug("Exception: ", t);	// Don't spam log with stacktraces in normal production cases
                        }
                	}
                    if (worker != null) {
                   		serviceSession.executeServiceInNoTransaction(worker, serviceName);
                    } else {
                    	Object o = timerInfo;
                    	if (serviceName != null) {
                    		o = serviceName;
                    	}
                    	logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                    			LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicerunonothernode", o));
                    }
                    if (new Date().getTime() - startOfTimeOut > serviceInterval * 1000) {
                    	log.warn("Service '" + serviceName + "' took longer than it's configured service interval."
                    			+ " This can trigger simultanious service execution on several nodes in a cluster."
                    			+ " Increase interval or lower each invocations work load.");
                    }
            	}
        	}
        }
        log.trace("<ejbTimeout");
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public IWorker getWorkerIfItShouldRun(Integer serviceId, long nextTimeout) {
    	IWorker worker = null;
        ServiceData serviceData = serviceDataSession.findById(serviceId);
        ServiceConfiguration serviceConfiguration = serviceData.getServiceConfiguration();
        if (!serviceConfiguration.isActive()) {
            if (log.isDebugEnabled()) {
            	log.debug("Service " + serviceId + " is inactive.");
            }
        	return null;	// Don't return an inactive worker to run
        }
        String serviceName = serviceData.getName();
        final String hostname = getHostName();
        if (shouldRunOnThisNode(hostname, Arrays.asList(serviceConfiguration.getPinToNodes()))) {
	        long oldRunTimeStamp = serviceData.getRunTimeStamp();
	        long oldNextRunTimeStamp = serviceData.getNextRunTimeStamp();
	        worker = getWorker(serviceConfiguration, serviceName, oldRunTimeStamp, oldNextRunTimeStamp);
	        if (worker.getNextInterval() == IInterval.DONT_EXECUTE) {
	            if (log.isDebugEnabled()) {
	            	log.debug("Service has interval IInterval.DONT_EXECUTE.");
	            }
	        	return null;	// Don't return an inactive worker to run
	        }
	        Date runDateCheck = new Date(oldNextRunTimeStamp); // nextRunDateCheck will typically be the same (or just a millisecond earlier) as now here
	        Date currentDate = new Date();
	        if (log.isDebugEnabled()) {
	        	Date nextRunDate = new Date(nextTimeout);
	        	log.debug("nextRunDate is:  " + nextRunDate);
	        	log.debug("runDateCheck is: " + runDateCheck);
	        	log.debug("currentDate is:  " + currentDate);
	        }
	        /*
	         * Check if the current date is after when the service should run. If a
	         * service on another cluster node has updated this timestamp already,
	         * then it will return false and this service will not run. This is a
	         * semaphore (not the best one admitted) so that services in a cluster
	         * only runs on one node and don't compete with each other. If a worker
	         * on one node for instance runs for a very long time, there is a chance
	         * that another worker on another node will break this semaphore and run
	         * as well.
	         */
	        if (currentDate.after(runDateCheck)) {
	            /*
	             * We only update the nextRunTimeStamp if the service is allowed to run on this node.
	             * 
	             * However, we need to make sure that no other node has already acquired the semaphore
	             * if our current database allows non-repeatable reads.
	             */
	        	if (!serviceDataSession.updateTimestamps(serviceId, oldRunTimeStamp, oldNextRunTimeStamp, runDateCheck.getTime(), nextTimeout)) {
	        		log.debug("Another node had already updated the database at this point. This node will not run.");
	        		worker = null;	// Failed to update the database.
	        	}
	        } else {
	        	worker = null;	// Don't return a worker, since this node should not run
	        }
        } else {
        	worker = null;
			if (log.isDebugEnabled()) {
				log.debug("Service " + serviceName + " will not run on this node: \"" + hostname + "\", Pinned to: " + Arrays.toString(serviceConfiguration.getPinToNodes()));
			}
        }
        return worker;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void executeServiceInNoTransaction(IWorker worker, String serviceName) {
        try {
			// Awkward way of letting POJOs get interfaces, but shows dependencies on the EJB level for all used classes. Injection wont work, since we have circular dependencies! 
        	Map<Class<?>, Object> ejbs = new HashMap<Class<?>, Object>();
        	ejbs.put(ApprovalSessionLocal.class, approvalSession);
        	ejbs.put(AuthenticationSessionLocal.class, authenticationSession);
        	ejbs.put(AuthorizationSessionLocal.class, authorizationSession);
        	ejbs.put(CAAdminSessionLocal.class, caAdminSession);
        	ejbs.put(CaSessionLocal.class, caSession);
        	ejbs.put(CertificateProfileSessionLocal.class, certificateProfileSession);
        	ejbs.put(CertificateStoreSessionLocal.class, certificateStoreSession);
        	ejbs.put(CrlCreateSessionLocal.class, crlCreateSession);
        	ejbs.put(EndEntityProfileSessionLocal.class, endEntityProfileSession);
        	ejbs.put(HardTokenSessionLocal.class, hardTokenSession);
        	ejbs.put(LogSessionLocal.class, logSession);
        	ejbs.put(KeyRecoverySessionLocal.class, keyRecoverySession);
        	ejbs.put(RaAdminSessionLocal.class, raAdminSession);
        	ejbs.put(GlobalConfigurationSessionLocal.class, globalConfigurationSession);
        	ejbs.put(SignSessionLocal.class, signSession);
        	ejbs.put(UserAdminSessionLocal.class, userAdminSession);
        	ejbs.put(PublisherQueueSessionLocal.class, publisherQueueSession);
        	ejbs.put(PublisherSessionLocal.class, publisherSession);
            worker.work(ejbs);
        	logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
        			LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecuted", serviceName));
        } catch (ServiceExecutionFailedException e) {
            logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecutionfailed", serviceName));
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging) {
        if (log.isTraceEnabled()) {
            log.trace(">changeService(name: " + name + ")");
        }
        boolean success = false;
        if (isAuthorizedToEditService(admin, serviceConfiguration)) {
        	if (serviceDataSession.updateServiceConfiguration(name, serviceConfiguration)) {
                success = true;
            } else {
                log.error("Can not find service to change: " + name);
            }
            if (success) {
                String msg = intres.getLocalizedMessage("services.serviceedited", name);
                if (!noLogging) {
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                            LogConstants.EVENT_INFO_SERVICESEDITED, msg);
                } else {
                    log.info(msg);
                }
            } else {
                String msg = intres.getLocalizedMessage("services.serviceedited", name);
                log.error(msg);
                if (!noLogging) {
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                            LogConstants.EVENT_ERROR_SERVICESEDITED, msg);
                } else {
                    log.error(msg);
                }
            }
        } else {
            String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
            if (!noLogging) {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                        msg);
            } else {
                log.error(msg);
            }
        }
        log.trace("<changeService()");
    }
    
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void load() {
        // Get all services
        Collection<Timer> currentTimers = timerService.getTimers(); 
        Iterator<Timer> iter = currentTimers.iterator();
        HashSet<Serializable> existingTimers = new HashSet<Serializable>();
        while (iter.hasNext()) {
            Timer timer = iter.next();
            try {
                Serializable info = timer.getInfo();
                existingTimers.add(info);
            } catch (Throwable e) {
                // EJB 2.1 only?: We need this try because weblogic seems to
                // suck...
                log.debug("Error invoking timer.getInfo(): ", e);
            }
        }

        // Get new services and add timeouts
        Map<Integer,Long> newTimeouts = serviceSession.getNewServiceTimeouts(existingTimers);
        for (Integer id : newTimeouts.keySet()) {
        	addTimer(newTimeouts.get(id), id);
        }

        if (!existingTimers.contains(SERVICELOADER_ID)) {
            // load the service timer
            addTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID); 
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public Map<Integer,Long> getNewServiceTimeouts(HashSet<Serializable> existingTimers) {
    	Map<Integer,Long> ret = new HashMap<Integer,Long>();
        HashMap<Integer, String> idToNameMap = getServiceIdToNameMap(intAdmin);
        Collection<Integer> allServices = idToNameMap.keySet();
        Iterator<Integer> iter2 = allServices.iterator();
        while (iter2.hasNext()) {
            Integer id = iter2.next();
            ServiceData htp = serviceDataSession.findById(id);
            if (htp != null) {
                if (!existingTimers.contains(id)) {
                	ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
                    IWorker worker = getWorker(serviceConfiguration, idToNameMap.get(id), htp.getRunTimeStamp(), htp.getNextRunTimeStamp());
                    if (worker != null && serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
                    	ret.put(id, Long.valueOf((worker.getNextInterval()) * 1000));
                    }
                }            	
            } else {
    			// Service does not exist, strange, but no panic.
    			log.debug("Can not find service with id "+id);
            }
        }
    	return ret;
    }

    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void unload() {
    	log.debug("Unloading all timers.");
        // Get all services
        for (Timer timer : (Collection<Timer>) timerService.getTimers()) {
            try {
                timer.cancel();
            } catch (Exception e) {
                /*
                 * EJB 2.1 only?: We need to catch this because Weblogic 10
                 * throws an exception if we have not scheduled this timer, so
                 * we don't have anything to cancel. Only weblogic though...
                 */
                log.info("Caught exception canceling timer: " + e.getMessage());
            }
        }
    }
    
    /**
     * Adds a timer to the bean, and cancels all existing timeouts for this id.
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method should not be run from within a transaction.
    private Timer addTimer(long interval, Integer id) {
        return timerService.createTimer(interval, id);
    }

    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method should not be run from within a transaction.
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void cancelTimer(Integer id) {
        for (Timer next : (Collection<Timer>) timerService.getTimers()) {
            try {
                if (id.equals(next.getInfo())) {
                    next.cancel();
                    break;
                }
            } catch (Exception e) {
                /*
                 * EJB 2.1 only?: We need to catch this because Weblogic 10
                 * throws an exception if we have not scheduled this timer, so
                 * we don't have anything to cancel. Only weblogic though...
                 */
                log.error("Caught exception canceling timer: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Method that creates a worker from the service configuration.
     * 
     * @param serviceConfiguration
     * @param serviceName
     * @param runTimeStamp the time this service runs
     * @param nextRunTimeStamp the time this service will run next time
     * @return a worker object or null if the worker is misconfigured.
     */
    private IWorker getWorker(ServiceConfiguration serviceConfiguration, String serviceName, long runTimeStamp, long nextRunTimeStamp) {
        IWorker worker = null;
        try {
            String clazz = serviceConfiguration.getWorkerClassPath();
            if (StringUtils.isNotEmpty(clazz)) {
                worker = (IWorker) Thread.currentThread().getContextClassLoader().loadClass(clazz).newInstance();
                worker.init(intAdmin, serviceConfiguration, serviceName, runTimeStamp, nextRunTimeStamp);
            } else {
                log.info("Worker has empty classpath for service " + serviceName);
            }
        } catch (Exception e) {
            // Only display a real error if it is a worker that we are actually
            // using
            if (serviceConfiguration.isActive()) {
                log.error("Worker is misconfigured, check the classpath", e);
            } else {
                log.info("Worker is misconfigured, check the classpath: " + e.getMessage());
            }
        }
        return worker;
    }
    
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public long getServiceInterval(Integer serviceId) {
    	long ret = IInterval.DONT_EXECUTE;
        ServiceData htp = serviceDataSession.findById(serviceId);
        if (htp != null) {
        	ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
            if (serviceConfiguration.isActive()) {
                IWorker worker = getWorker(serviceConfiguration, "temp", 0, 0);	// A bit dirty, but it works..
                if (worker!=null) {
                    ret = worker.getNextInterval();
                }
            } else {
                if (log.isDebugEnabled()) {
                	log.debug("Service " + serviceId + " is inactive.");
                }
            }
        }
        return ret;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ServiceConfiguration getServiceConfiguration(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getServiceConfiguration: " + id);
        }
        ServiceConfiguration returnval = null;
        try {
            ServiceData serviceData = serviceDataSession.findById(Integer.valueOf(id));
            if (serviceData != null) {
                returnval = serviceData.getServiceConfiguration();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Returnval is null for service id: " + id);
                }
            }
        } catch (Exception e) {
            // return null if we cant find it, if it is not due to underlying
            // database error
            log.debug("Got an Exception for service with id " + id + ": " + e.getMessage());
            /*
             * If we don't re-throw here it will be treated as the service id
             * does not exist and the service will not be rescheduled to run.
             */
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getServiceConfiguration: " + id);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer, String> getServiceIdToNameMap(Admin admin) {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<ServiceData> result = serviceDataSession.findAll();
        Iterator<ServiceData> i = result.iterator();
        while (i.hasNext()) {
            ServiceData next = i.next();
            returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }
    
    /**
     * Method to check if an admin is authorized to edit a service The following
     * checks are performed.
     * 
     * 1. Deny If the service is hidden and the admin is internal EJBCA 2. Allow
     * If the admin is an super administrator 3. Deny all other
     * 
     * @return true if the administrator is authorized
     */
    private boolean isAuthorizedToEditService(Admin admin, ServiceConfiguration serviceConfiguraion) {
        
        if (serviceConfiguraion.isHidden() && admin.getAdminType() != Admin.TYPE_INTERNALUSER) {
            return false;
        } else if (serviceConfiguraion.isHidden() && admin.getAdminType() == Admin.TYPE_INTERNALUSER) {
            return true;
        }
        if (authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            return true;
        }

        return false;
    }
    
    /**
     * Return true if the service should run on the node given the list of nodes it is pinned to. An empty list means that the service
     * is not pinned to any particular node and should run on all.
     * @param nodes list of nodes the service is pinned to
     * @return true if the service should run on this node
     */
    private boolean shouldRunOnThisNode(final String hostname, final List<String> nodes) {
    	final boolean result;
    	if (nodes == null || nodes.isEmpty()) {
    		result = true;
    	} else if (hostname == null) {
    		result = false;
    	} else {
    		result = nodes.contains(hostname);
    	}
		return result;
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
