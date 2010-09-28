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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
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
 * 
 * @ejb.bean 
 *           description="Session bean handling interface with service configuration"
 *           display-name="ServiceSessionSB" name="ServiceSession"
 *           jndi-name="ServiceSession" local-jndi-name="ServiceSessionLocal"
 *           view-type="both" type="Stateless" transaction-type="Container"
 * 
 * @ejb.transaction type="Required"
 * 
 * @weblogic.enable-call-by-reference True
 * 
 * @ejb.env-entry name="DataSource" type="java.lang.String"
 *                value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 * 
 * @ejb.home extends="javax.ejb.EJBHome" local-extends="javax.ejb.EJBLocalHome"
 *           local-class="org.ejbca.core.ejb.services.IServiceSessionLocalHome"
 *           remote-class="org.ejbca.core.ejb.services.IServiceSessionHome"
 * 
 * @ejb.interface extends="javax.ejb.EJBObject"
 *                local-extends="javax.ejb.EJBLocalObject"
 *                local-class="org.ejbca.core.ejb.services.IServiceSessionLocal"
 *                remote
 *                -class="org.ejbca.core.ejb.services.IServiceSessionRemote"
 * 
 * @ejb.ejb-external-ref description="The Service entity bean" view-type="local"
 *                       ref-name="ejb/ServiceDataLocal" type="Entity"
 *                       home="org.ejbca.core.ejb.services.ServiceDataLocalHome"
 *                       business="org.ejbca.core.ejb.services.ServiceDataLocal"
 *                       link="ServiceData"
 * 
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *                       view-type="local"
 *                       ref-name="ejb/AuthorizationSessionLocal" type="Session"
 *                       home=
 *                       "org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *                       link="AuthorizationSession"
 * 
 * @ejb.ejb-external-ref description="The log session bean" view-type="local"
 *                       ref-name="ejb/LogSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *                       business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *                       link="LogSession"
 * 
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *                       view-type="local" ref-name="ejb/CAAdminSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *                       link="CAAdminSession"
 * 
 * @ejb.ejb-external-ref description="The Service Timer Session Bean"
 *                       view-type="local"
 *                       ref-name="ejb/ServiceTimerSessionLocal" type="Session"
 *                       home=
 *                       "org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.services.IServiceTimerSessionLocal"
 *                       link="ServiceTimerSession"
 * 
 * @ejb.ejb-external-ref 
 *                       description="The Certificate store used to store and fetch certificates"
 *                       view-type="local"
 *                       ref-name="ejb/CertificateStoreSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *                       link="CertificateStoreSession"
 * 
 * @jonas.bean ejb-name="ServiceSession"
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
    private TimerService timerService;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private ServiceDataSessionLocal serviceDataSession;
    @EJB
    private LogSessionLocal logSession;
    
    /**
     * The administrator that the services should be run as.
     */
    private Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);

  

    /**
     * Adds a Service to the database.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void addService(Admin admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ")");
        }
        addService(admin, findFreeServiceId().intValue(), name, serviceConfiguration);
        log.trace("<addService()");
    }

    /**
     * Adds a service to the database. Used for importing and exporting profiles
     * from xml-files.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @ejb.interface-method view-type="both"
     */
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



    /**
     * Adds a service with the same content as the original.
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
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

    /**
     * Removes a service from the database.
     * 
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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
                IWorker worker = getWorker(serviceConfiguration, name);
                if (worker != null) {
                    cancelTimer(htp.getId());
                }
                serviceDataSession.removeServiceData(htp);
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

    /**
     * Renames a service
     * 
     * @throws ServiceExistsException
     *             if service already exists.
     * @ejb.interface-method view-type="both"
     */
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

    /**
     * Retrieves a Collection of id:s (Integer) to visible authorized services.
     * Currently is the only check if the superadmin can see them all
     * 
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection<Integer> getAuthorizedVisibleServiceIds(Admin admin) {
        Collection<Integer> allServiceIds = new ArrayList<Integer>();
        Collection<Integer> allVisibleServiceIds = new ArrayList<Integer>();
        // If superadmin return all visible services
        try {
            authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
            allServiceIds = getServiceIdToNameMap(admin).keySet();
            Iterator<Integer> i = allServiceIds.iterator();
            while (i.hasNext()) {
                int id = i.next().intValue();
                // Remove hidden services here..
                if (!getServiceConfiguration(admin, id).isHidden()) {
                    allVisibleServiceIds.add(new Integer(id));
                }
            }
        } catch (AuthorizationDeniedException e) {
            log.debug("AuthorizationDeniedException: ", e);
        }
        return allVisibleServiceIds;
    }



    /**
     * Retrives a named service.
     * 
     * @returns the service configuration or null if it doesn't exist.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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



    /**
     * Returns a service id, given it's service name
     * 
     * @return the id or 0 if the service cannot be found.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getServiceId(Admin admin, String name) {
        int returnval = 0;
        ServiceData serviceData = serviceDataSession.findByName(name);
        if (serviceData != null) {
            returnval = serviceData.getId();
        }
        return returnval;
    }



    /**
     * Activates the timer for a named service. The service must already be
     * previously added.
     * 
     * @param admin
     *            The administrator performing the action
     * @param name
     *            the name of the service for which to activate the timer
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void activateServiceTimer(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">activateServiceTimer(name: " + name + ")");
        }
        ServiceData htp = serviceDataSession.findByName(name);
        if (htp != null) {
            ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
            if (isAuthorizedToEditService(admin, serviceConfiguration)) {
                IWorker worker = getWorker(serviceConfiguration, name);
                if (worker != null) {
                    cancelTimer(htp.getId());
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
    
    /**
     * Returns a Service name given its id.
     * 
     * @return the name or null if id doesnt exists
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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
     * @param timer
     *            timer whose expiration caused this notification.
     */
    @Timeout
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void timeoutHandler(Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">ejbTimeout");
        }
        Integer timerInfo = (Integer) timer.getInfo();
        if (timerInfo.equals(SERVICELOADER_ID)) {
            if (log.isDebugEnabled()) {
                log.debug("Running the internal Service loader.");
            }
            load();
        } else {
            ServiceConfiguration serviceData = null;
            IWorker worker = null;
            String serviceName = null;
            boolean run = false;
            try {
                serviceData = getServiceConfiguration(intAdmin, timerInfo.intValue());
                if (serviceData != null) {
                    serviceName = getServiceName(intAdmin, timerInfo.intValue());
                    worker = getWorker(serviceData, serviceName);
                    // This might lead to a circular dependency when using EJB
                    // injection..
                    run = checkAndUpdateServiceTimeout(worker.getNextInterval(), timerInfo, serviceData, serviceName);
                    log.debug("Service will run: " + run);
                } else {
                    log.debug("Service was null and will not run, neither will it be rescheduled, so it will never run. Id: " + timerInfo.intValue());
                }
            } catch (Throwable e) {
                // We need to catch wide here in order to continue even if there
                // is some error
                log.info("Error getting and running service, we must see if we need to re-schedule: " + e.getMessage());
                if (log.isDebugEnabled()) {
                    // Don't spam log with stacktraces in normal production
                    // cases
                    log.debug("Exception: ", e);
                }

                // Check if we have scheduled this timer to run again, or if this
                // exception would stop the service from running for ever.
                // If we can't find any current timer we will try to create a
                // new one.
                boolean isScheduledToRun = false;
                Collection<Timer> timers = timerService.getTimers(); 
                for (Iterator<Timer> iterator = timers.iterator(); iterator.hasNext();) {
                    Timer t = iterator.next();
                    Integer tInfo = (Integer) t.getInfo();
                    if (tInfo.intValue() == timerInfo.intValue()) {
                        Date nextTimeOut = t.getNextTimeout();
                        Date now = new Date();
                        if (log.isDebugEnabled()) {
                            log.debug("Next timeout for existing timer is '" + nextTimeOut + "' now is '" + now + "'");
                        }
                        if (nextTimeOut.after(now)) {
                            // Yes we found a timer that is scheduled for this
                            // service
                            isScheduledToRun = true;
                        }
                    }
                }
                if (!isScheduledToRun) {
                    long nextInterval = 60; // Default try to run again in 60
                    // seconds in case of error
                    if (worker != null) {
                        nextInterval = worker.getNextInterval();
                    }
                    long intervalMillis = getNextIntervalMillis(nextInterval);
                    addTimer(intervalMillis, timerInfo); 
                    String msg = intres.getLocalizedMessage("services.servicefailedrescheduled", intervalMillis);
                    log.info(msg);
                }
            }
            if (run) {
                if (serviceData != null) {
                    try {
                        if (serviceData.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
                            worker.work();
                            logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                                    LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecuted", serviceName));
                        }
                    } catch (ServiceExecutionFailedException e) {
                        logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                                LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecutionfailed", serviceName));
                    }
                } else {
                    logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                            LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicenotfound", timerInfo));
                }
            } else {
                Object o = timerInfo;
                if (serviceName != null) {
                    o = serviceName;
                }
                logSession.log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicerunonothernode", o));
            }
        }
        log.trace("<ejbTimeout");
    }

    /**
     * Internal method should not be called from external classes, method is
     * public to get automatic transaction handling.
     * 
     * This method need "RequiresNew" transaction handling, because we want to
     * make sure that the timer runs the next time even if the execution fails.
     * 
     * @return true if the service should run, false if the service should not
     *         run
     * 
     * @ejb.interface-method view-type="local"
     * @ejb.transaction type="RequiresNew"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public boolean checkAndUpdateServiceTimeout(long nextInterval, int timerInfo, ServiceConfiguration serviceData, String serviceName) {
        boolean ret = false;
        /*
         * Add a random delay within 30 seconds to the interval, just to make
         * sure nodes in a cluster are not scheduled to run on the exact same
         * second. If the next scheduled run is less than 40 seconds away, we
         * only randomize on 5 seconds.
         */
        long intervalMillis = getNextIntervalMillis(nextInterval);
        addTimer(intervalMillis, timerInfo); 
        // Calculate the nextRunTimeStamp, since we set a new timer
        Date runDateCheck = serviceData.getNextRunTimestamp();  
        /*
         * nextRunDateCheck will typically be the same (or just a millisecond earlier) as now
         * here
         */
        Date currentDate = new Date();
        Date nextRunDate = new Date(currentDate.getTime() + intervalMillis);
        if (log.isDebugEnabled()) {
            log.debug("nextRunDate is: " + nextRunDate);
            log.debug("runDateCheck is: " + runDateCheck);
            log.debug("currentDate is: " + currentDate);
        }
        /*
         * Check if the current date is after when the service should run. If a
         * service on another cluster node has updated this timestamp already,
         * then it will return false and this service will not run. This is a
         * semaphor (not the best one admitted) so that services in a cluster
         * only runs on one node and don't compete with each other. If a worker
         * on one node for instance runs for a very long time, there is a chance
         * that another worker on another node will break this semaphore and run
         * as well.
         */
        if (currentDate.after(runDateCheck)) {
            /*
             * We only update the nextRunTimeStamp if the service will be
             * running otherwise it will, in theory, be a race to exclude each
             * other between the nodes.
             */
            serviceData.setNextRunTimestamp(nextRunDate);
            changeService(intAdmin, serviceName, serviceData, true);
            ret = true;
        }
        return ret;
    }

    /**
     * Updates service configuration, but does not re-set the timer
     * 
     * @param noLogging
     *            if true no logging (to the database will be done
     * 
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging) {
        if (log.isTraceEnabled()) {
            log.trace(">changeService(name: " + name + ")");
        }
        boolean success = false;
        if (isAuthorizedToEditService(admin, serviceConfiguration)) {
            ServiceData htp = serviceDataSession.findByName(name);
            if (htp != null) {
                htp.setServiceConfiguration(serviceConfiguration);
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
    
    private long getNextIntervalMillis(long nextIntervalSecs) {
        Date currentDate = new Date();
        Date nextApproxTime = new Date(currentDate.getTime() + nextIntervalSecs * 1000);
        Date fourtysec = new Date(currentDate.getTime() + 40100); // add 100
        // milliseconds
        Date threesec = new Date(currentDate.getTime() + 3100); // add 100
        // milliseconds
        int randInterval = 30000;
        if (fourtysec.after(nextApproxTime)) {
            // If we are running with less than 40 second intervale we only
            // randomize 5 seconds
            randInterval = 5000;
            // And if we are running with a very short interval we only
            // randomize on one second
            if (threesec.after(nextApproxTime)) {
                randInterval = 1000;
            }
        }
        Random rand = new Random();
        int randMillis = rand.nextInt(randInterval);
        if (log.isDebugEnabled()) {
            log.debug("Adding random delay: " + randMillis);
        }

        long intervalMillis = nextIntervalSecs * 1000 + randMillis;
        return intervalMillis;
    }

    /**
     * Loads and activates all the services from database that are active
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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

        HashMap<Integer, String> idToNameMap = getServiceIdToNameMap(intAdmin);
        Collection<Integer> allServices = idToNameMap.keySet();
        Iterator<Integer> iter2 = allServices.iterator();
        while (iter2.hasNext()) {
            Integer id = iter2.next();
            ServiceConfiguration serviceConfiguration = getServiceConfiguration(intAdmin, id.intValue());
            if (!existingTimers.contains(id)) {
                IWorker worker = getWorker(serviceConfiguration, idToNameMap.get(id));
                if (worker != null && serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
                   addTimer((worker.getNextInterval()) * 1000, id);
                }
            }
        }

        if (!existingTimers.contains(SERVICELOADER_ID)) {
            // load the service timer
            addTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID); 
        }
    }

    /**
     * Cancels all existing timers a unload
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void unload() {
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
     * 
     * @param id
     *            the id of the timer
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void addTimer(long interval, Integer id) {
        timerService.createTimer(interval, id);

    }

    /**
     * cancels a timer with the given Id
     * 
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
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
     * @return a worker object or null if the worker is misconfigured.
     */
    private IWorker getWorker(ServiceConfiguration serviceConfiguration, String serviceName) {
        IWorker worker = null;
        try {
            String clazz = serviceConfiguration.getWorkerClassPath();
            if (StringUtils.isNotEmpty(clazz)) {
                worker = (IWorker) Thread.currentThread().getContextClassLoader().loadClass(clazz).newInstance();
                worker.init(intAdmin, serviceConfiguration, serviceName);
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
    
    /**
     * Finds a service configuration by id.
     * 
     * @returns the service configuration or null if it doesn't exist.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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
    

    
    /**
     * Method creating a hashmap mapping service id (Integer) to service name
     * (String).
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
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
        try {
            if (serviceConfiguraion.isHidden() && admin.getAdminType() != Admin.TYPE_INTERNALUSER) {
                return false;
            } else if (serviceConfiguraion.isHidden() && admin.getAdminType() == Admin.TYPE_INTERNALUSER) {
                return true;
            }
            if (authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                return true;
            }
        } catch (AuthorizationDeniedException e) {
        }
        return false;
    }
    
}
