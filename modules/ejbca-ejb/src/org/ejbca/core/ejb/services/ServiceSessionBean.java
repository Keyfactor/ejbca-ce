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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.util.ProfileID;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;

/**
 * Session bean that handles adding and editing services as displayed in EJBCA. This bean manages the service configuration as stored in the database,
 * and executes services at timeouts triggered by the timeoutHandler.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ServiceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ServiceSessionBean implements ServiceSessionLocal, ServiceSessionRemote {

    private static final Logger log = Logger.getLogger(ServiceSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /**
     * Constant indicating the Id of the "service loader" service. Used in a clustered environment to periodically load available services
     */
    private static final Integer SERVICELOADER_ID = 0;

    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

    @Resource
    private SessionContext sessionContext;
    private TimerService timerService; // When the sessionContext is injected, the timerService should be looked up.

    @EJB
    private AccessControlSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private InternalSecurityEventsLoggerSessionLocal internalAuditSession;
    @EJB
    private ServiceDataSessionLocal serviceDataSession;

    private ServiceSessionLocal serviceSession;

    // Additional dependencies from the services we executeServiceInTransaction
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private EndEntityAuthenticationSessionLocal authenticationSession;
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
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private AdminPreferenceSessionLocal raAdminSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private CertificateRequestSessionLocal certificateRequestSession;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationSession;
    @EJB
    private ComplexAccessControlSessionLocal complexAccessControlSession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenSession;
    @EJB
    private CmpMessageDispatcherSessionLocal cmpMsgDispatcherSession;

    // The administrator that the services should be run as. Internal, allow all.
    private AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ServiceSession"));

    @PostConstruct
    public void ejbCreate() {
        timerService = sessionContext.getTimerService();
        serviceSession = sessionContext.getBusinessObject(ServiceSessionLocal.class);
    }

    @Override
    public void addService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ")");
        }
        addService(admin, findFreeServiceId(), name, serviceConfiguration);
        log.trace("<addService()");
    }

    @Override
    public void addService(AuthenticationToken admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ", id: " + id + ")");
        }
        boolean success = addServiceInternal(admin, id, name, serviceConfiguration);
        if (success) {
            final String msg = intres.getLocalizedMessage("services.serviceadded", name);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.SERVICE_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            final String msg = intres.getLocalizedMessage("services.erroraddingservice", name);
            log.info(msg);
            throw new ServiceExistsException(msg);
        }
        log.trace("<addService()");
    }
    
    private boolean addServiceInternal(AuthenticationToken admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        boolean success = false;
        if (isAuthorizedToEditService(admin)) {
            if (serviceDataSession.findByName(name) == null) {
                if (serviceDataSession.findById(Integer.valueOf(id)) == null) {
                    serviceDataSession.addServiceData(id, name, serviceConfiguration);
                    success = true;
                }
            }
        } else {
            final String msg = intres.getLocalizedMessage("services.notauthorizedtoadd", name);
            log.info(msg);
        }
        return success;
    }

    @Override
    public void cloneService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException {
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
            if (isAuthorizedToEditService(admin)) {
                addServiceInternal(admin, findFreeServiceId(), newname, servicedata);
                final String msg = intres.getLocalizedMessage("services.servicecloned", newname, oldname);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.SERVICE_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
            } else {
                final String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", oldname);
                log.info(msg);
            }
        } catch (CloneNotSupportedException e) {
            log.error("Error cloning service: ", e);
            throw new EJBException(e);
        }
        log.trace("<cloneService()");
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean removeService(AuthenticationToken admin, String name) {
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
            if (isAuthorizedToEditService(admin)) {
                IWorker worker = getWorker(serviceConfiguration, name, htp.getRunTimeStamp(), htp.getNextRunTimeStamp());
                if (worker != null) {
                    serviceSession.cancelTimer(htp.getId());
                }
                serviceDataSession.removeServiceData(htp.getId());
                final String msg = intres.getLocalizedMessage("services.serviceremoved", name);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.SERVICE_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
                retval = true;
            } else {
                final String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
                log.info(msg);
            }
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("services.errorremovingservice", name);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("error", e.getMessage());
            auditSession.log(EjbcaEventTypes.SERVICE_REMOVE, EventStatus.FAILURE, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        }
        log.trace("<removeService)");
        return retval;
    }

    @Override
    public void renameService(AuthenticationToken admin, String oldname, String newname) throws ServiceExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renameService(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        if (serviceDataSession.findByName(newname) == null) {
            ServiceData htp = serviceDataSession.findByName(oldname);
            if (htp != null) {
                if (isAuthorizedToEditService(admin)) {
                    htp.setName(newname);
                    success = true;
                } else {
                    final String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", oldname);
                    log.info(msg);
                }
            }
        }
        if (success) {
            final String msg = intres.getLocalizedMessage("services.servicerenamed", oldname, newname);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.SERVICE_RENAME, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            final String msg = intres.getLocalizedMessage("services.errorrenamingservice", oldname, newname);
            log.info(msg);
            throw new ServiceExistsException(msg);
        }
        log.trace("<renameService()");
    }

    @Override
    public Collection<Integer> getVisibleServiceIds() {
        Collection<Integer> allVisibleServiceIds = new ArrayList<Integer>();
            Collection<Integer> allServiceIds = getServiceIdToNameMap().keySet();
            for (int id : allServiceIds) {
                // Remove hidden services here..
                if (!getServiceConfiguration(id).isHidden()) {
                    allVisibleServiceIds.add(Integer.valueOf(id));
                }
            }

        return allVisibleServiceIds;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ServiceConfiguration getService(String name) {
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
    public int getServiceId(String name) {
        int returnval = 0;
        ServiceData serviceData = serviceDataSession.findByName(name);
        if (serviceData != null) {
            returnval = serviceData.getId();
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void activateServiceTimer(AuthenticationToken admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">activateServiceTimer(name: " + name + ")");
        }
        ServiceData htp = serviceDataSession.findByName(name);
        if (htp != null) {
            ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
            if (isAuthorizedToEditService(admin)) {
                IWorker worker = getWorker(serviceConfiguration, name, htp.getRunTimeStamp(), htp.getNextRunTimeStamp());
                if (worker != null) {
                    serviceSession.cancelTimer(htp.getId());
                    if (serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE) {
                        addTimer(worker.getNextInterval() * 1000, htp.getId());
                    }
                }
            } else {
                final String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
                log.info(msg);
            }
        } else {
            log.error("Can not find service: " + name);
        }
        log.trace("<activateServiceTimer()");
    }

    private int findFreeServiceId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return ServiceSessionBean.this.serviceDataSession.findById(Integer.valueOf(i))==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getServiceName(int id) {
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
     * Method implemented from the TimerObject and is the main method of this session bean. It calls the work object for each object.
     * 
     * @param timer timer whose expiration caused this notification.
     */
    @Timeout
    // Glassfish 2.1.1:
    // "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
    // JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions.
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">ejbTimeout");
        }
        final long startOfTimeOut = System.currentTimeMillis();
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
            } catch (Throwable t) { // NOPMD: we really need to catch everything to not risk hanging somewhere in limbo
                log.warn("Exception finding service name: ", t); // if this throws, there is a failed database or similar
                // Unexpected error (probably database related). We need to reschedule the service w a default interval.
                addTimer(30 * 1000, timerInfo);
            }
            if (serviceName == null) {
                final String msg = intres.getLocalizedMessage("services.servicenotfound", timerInfo);
                log.info(msg);
            } else {
                // Get interval of worker
                try {
                    serviceInterval = serviceSession.getServiceInterval(timerInfo);
                } catch (Throwable t) { // NOPMD: we really need to catch everything to not risk hanging somewhere in limbo
                    log.warn("Exception getting service interval: ", t); // if this throws, there is a failed database or similar
                    // Unexpected error (probably database related). We need to reschedule the service w a default interval.
                    addTimer(30 * 1000, timerInfo);
                }
                // Reschedule timer
                IWorker worker = null;
                if (serviceInterval != IInterval.DONT_EXECUTE) {
                    Timer nextTrigger = addTimer(serviceInterval * 1000, timerInfo);
                    try {
                        // Try to acquire lock / see if this node should run
                        worker = serviceSession.getWorkerIfItShouldRun(timerInfo, nextTrigger.getNextTimeout().getTime());
                    } catch (Throwable t) { // NOPMD: we really need to catch everything to not risk hanging somewhere in limbo
                        if (log.isDebugEnabled()) {
                            log.debug("Exception: ", t); // Don't spam log with stacktraces in normal production cases
                        }
                    }
                    if (worker != null) {
                        try {
                            serviceSession.executeServiceInNoTransaction(worker, serviceName);
                        } catch (RuntimeException e) {
                            /*
                             * If the service worker fails with a RuntimeException we need to
                             * swallow this here. If we allow it to propagate outside the
                             * ejbTimeout method it is up to the application server config how it
                             * should be retried, but we have already scheduled a new try
                             * previously in this method. We still want to log this as an ERROR
                             * since it is some kind of catastrophic failure..
                             */
                            log.error("Service worker execution failed.", e);
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            Object o = timerInfo;
                            if (serviceName != null) {
                                o = serviceName;
                            }
                            final String msg = intres.getLocalizedMessage("services.servicerunonothernode", o);
                            log.debug(msg);
                        }
                    }
                    if (System.currentTimeMillis() - startOfTimeOut > serviceInterval * 1000) {
                        log.warn("Service '" + serviceName + "' took longer than it's configured service interval ("+serviceInterval+")."
                                + " This can trigger simultanious service execution on several nodes in a cluster."
                                + " Increase interval or lower each invocations work load.");
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<ejbTimeout");
        }
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
            return null; // Don't return an inactive worker to run
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
                return null; // Don't return an inactive worker to run
            }
            Date runDateCheck = new Date(oldNextRunTimeStamp); // nextRunDateCheck will typically be the same (or just a millisecond earlier) as now
                                                               // here
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
                    worker = null; // Failed to update the database.
                }
            } else {
                worker = null; // Don't return a worker, since this node should not run
            }
        } else {
            worker = null;
            if (log.isDebugEnabled()) {
                log.debug("Service " + serviceName + " will not run on this node: \"" + hostname + "\", Pinned to: "
                        + Arrays.toString(serviceConfiguration.getPinToNodes()));
            }
        }
        return worker;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void executeServiceInNoTransaction(IWorker worker, String serviceName) {
        try {
            // Awkward way of letting POJOs get interfaces, but shows dependencies on the EJB level for all used classes. Injection wont work, since
            // we have circular dependencies!
            Map<Class<?>, Object> ejbs = new HashMap<Class<?>, Object>();
            ejbs.put(ApprovalSessionLocal.class, approvalSession);
            ejbs.put(EndEntityAuthenticationSessionLocal.class, authenticationSession);
            ejbs.put(AccessControlSessionLocal.class, authorizationSession);
            ejbs.put(CAAdminSessionLocal.class, caAdminSession);
            ejbs.put(CaSessionLocal.class, caSession);
            ejbs.put(CertificateProfileSessionLocal.class, certificateProfileSession);
            ejbs.put(CertificateStoreSessionLocal.class, certificateStoreSession);
            ejbs.put(CrlCreateSessionLocal.class, crlCreateSession);
            ejbs.put(CrlStoreSessionLocal.class, crlStoreSession);
            ejbs.put(EndEntityProfileSessionLocal.class, endEntityProfileSession);
            ejbs.put(HardTokenSessionLocal.class, hardTokenSession);
            ejbs.put(SecurityEventsLoggerSessionLocal.class, auditSession);
            ejbs.put(InternalSecurityEventsLoggerSessionLocal.class, internalAuditSession);
            ejbs.put(KeyRecoverySessionLocal.class, keyRecoverySession);
            ejbs.put(AdminPreferenceSessionLocal.class, raAdminSession);
            ejbs.put(GlobalConfigurationSessionLocal.class, globalConfigurationSession);
            ejbs.put(SignSessionLocal.class, signSession);
            ejbs.put(EndEntityManagementSessionLocal.class, endEntityManagementSession);
            ejbs.put(PublisherQueueSessionLocal.class, publisherQueueSession);
            ejbs.put(PublisherSessionLocal.class, publisherSession);
            ejbs.put(CertificateRequestSessionLocal.class, certificateRequestSession);
            ejbs.put(EndEntityAccessSessionLocal.class, endEntityAccessSession);
            ejbs.put(WebAuthenticationProviderSessionLocal.class, webAuthenticationSession);
            ejbs.put(ComplexAccessControlSessionLocal.class, complexAccessControlSession);
            ejbs.put(PublishingCrlSessionLocal.class, publishingCrlSession);
            ejbs.put(CryptoTokenManagementSessionLocal.class, cryptoTokenSession);
            ejbs.put(CmpMessageDispatcherSessionLocal.class, cmpMsgDispatcherSession);
            worker.work(ejbs);
            final String msg = intres.getLocalizedMessage("services.serviceexecuted", serviceName);
            log.info(msg);
        } catch (ServiceExecutionFailedException e) {
            final String msg = intres.getLocalizedMessage("services.serviceexecutionfailed", serviceName);
            log.info(msg, e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void changeService(AuthenticationToken admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging) {
        if (log.isTraceEnabled()) {
            log.trace(">changeService(name: " + name + ")");
        }
        if (isAuthorizedToEditService(admin)) {
            ServiceData oldservice = serviceDataSession.findByName(name);
            if (oldservice != null) {
                final Map<Object, Object> diff = oldservice.getServiceConfiguration().diff(serviceConfiguration);
                if (serviceDataSession.updateServiceConfiguration(name, serviceConfiguration)) {
                    final String msg = intres.getLocalizedMessage("services.serviceedited", name);
                    if (noLogging) {
                        log.info(msg);
                    } else {
                        final Map<String, Object> details = new LinkedHashMap<String, Object>();
                        details.put("msg", msg);
                        for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                            details.put(entry.getKey().toString(), entry.getValue().toString());
                        }
                        auditSession.log(EjbcaEventTypes.SERVICE_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                                intAdmin.toString(), null, null, null, details);
                    }
                } else {
                    String msg = intres.getLocalizedMessage("services.serviceedited", name);
                    if (noLogging) {
                        log.error(msg);
                    } else {
                        final Map<String, Object> details = new LinkedHashMap<String, Object>();
                        details.put("msg", msg);
                        auditSession.log(EjbcaEventTypes.SERVICE_EDIT, EventStatus.FAILURE, EjbcaModuleTypes.SERVICE, EjbcaServiceTypes.EJBCA,
                                intAdmin.toString(), null, null, null, details);
                    }
                }
            } else {
                log.error("Can not find service to change: " + name);
            }
        } else {
            String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
            log.info(msg);
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
            } catch (Throwable e) { // NOPMD: we really need to catch everything to not risk hanging somewhere in limbo
                // EJB 2.1 only?: We need this try because weblogic seems to ... suck ...
                log.debug("Error invoking timer.getInfo(): ", e);
            }
        }

        // Get new services and add timeouts
        Map<Integer, Long> newTimeouts = serviceSession.getNewServiceTimeouts(existingTimers);
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
    public Map<Integer, Long> getNewServiceTimeouts(HashSet<Serializable> existingTimers) {
        Map<Integer, Long> ret = new HashMap<Integer, Long>();
        HashMap<Integer, String> idToNameMap = getServiceIdToNameMap();
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
                log.debug("Can not find service with id " + id);
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
     * Adds a timer to the bean
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private Timer addTimer(long interval, Integer id) {
        if (log.isDebugEnabled()) {
            log.debug("addTimer: " + id);
        }
        return timerService.createTimer(interval, id);
    }

    /**
     * Cancels all existing timeouts for this id.
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void cancelTimer(Integer id) {
        if (log.isDebugEnabled()) {
            log.debug("cancelTimer: " + id);
        }
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
                IWorker worker = getWorker(serviceConfiguration, "temp", 0, 0); // A bit dirty, but it works..
                if (worker != null) {
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
    public ServiceConfiguration getServiceConfiguration(int id) {
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
    public HashMap<Integer, String> getServiceIdToNameMap() {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<ServiceData> result = serviceDataSession.findAll();
        for(ServiceData next : result) {
            returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> getServicesUsingCertificateProfile(Integer certificateProfileId) {
        List<String> result = new ArrayList<String>();
        //Since the service types are embedded in the data objects there is no more elegant way to to this.
        List<ServiceData> allServices = serviceDataSession.findAll();
        for (ServiceData service : allServices) {
            String certificateProfiles = service.getServiceConfiguration().getWorkerProperties()
                    .getProperty(BaseWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK);
            if (certificateProfiles != null && !certificateProfiles.equals("")) {
                for (String certificateProfile : certificateProfiles.split(";")) {
                    if (certificateProfile.equals(certificateProfileId.toString())) {
                        result.add(service.getName());
                        break;
                    }
                }
            }
        }
        return result;
    }
    
    /**
     * Method to check if an admin is authorized to edit a service. Allow access for /services/edit
     * 
     * @return true if the administrator is authorized
     */
    private boolean isAuthorizedToEditService(AuthenticationToken admin) {
       return authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.SERVICES_EDIT);            
    }

    /**
     * Return true if the service should run on the node given the list of nodes it is pinned to. An empty list means that the service is not pinned
     * to any particular node and should run on all.
     * 
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
