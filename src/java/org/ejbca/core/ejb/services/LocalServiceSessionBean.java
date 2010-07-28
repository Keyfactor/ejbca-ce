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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timer;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

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
import org.ejbca.core.model.services.ServiceExistsException;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @version $Id$
 *
 * @ejb.bean description="Session bean handling interface with service configuration"
 *   display-name="ServiceSessionSB"
 *   name="ServiceSession"
 *   jndi-name="ServiceSession"
 *   local-jndi-name="ServiceSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *   
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.services.IServiceSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.services.IServiceSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.services.IServiceSessionLocal"
 *   remote-class="org.ejbca.core.ejb.services.IServiceSessionRemote"
 *
 * @ejb.ejb-external-ref description="The Service entity bean"
 *   view-type="local"
 *   ref-name="ejb/ServiceDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.services.ServiceDataLocalHome"
 *   business="org.ejbca.core.ejb.services.ServiceDataLocal"
 *   link="ServiceData"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *   
 * @ejb.ejb-external-ref
 *   description="ProtectedLogSessionBean"
 *   view-type="local"
 *   ref-name="ejb/ProtectedLogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.IProtectedLogSessionLocal"
 *   link="ProtectedLogSession"
 *   
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *   
 * @ejb.ejb-external-ref description="The Service Timer Session Bean"
 *   view-type="local"
 *   ref-name="ejb/ServiceTimerSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome"
 *   business="org.ejbca.core.ejb.services.IServiceTimerSessionLocal"
 *   link="ServiceTimerSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 *  @jonas.bean ejb-name="ServiceSession"
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ServiceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LocalServiceSessionBean implements ServiceSessionLocal, ServiceSessionRemote {

	private static final Logger log = Logger.getLogger(LocalServiceSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;
	//This might lead to a circular dependency when using EJB injection..
    /*@EJB
	private ServiceTimerSessionLocal serviceTimerSession;*/
	@EJB
    private AuthorizationSessionLocal authorizationSession;
	@EJB
    private LogSessionLocal logSession;

    /**
     * The administrator that the services should be runned as.
     */
    private Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
    
   /**
    * Method that creates a worker from the service configuration. 
    * 
    * @param serviceConfiguration
    * @param serviceName
    * @return a worker object or null if the worker is missconfigured.
    */
    private IWorker getWorker(ServiceConfiguration serviceConfiguration, String serviceName) {
		IWorker worker = null;
    	try {
    		String cp = serviceConfiguration.getWorkerClassPath();
    		if (StringUtils.isNotEmpty(cp)) {
    			worker = (IWorker) Thread.currentThread().getContextClassLoader().loadClass(cp).newInstance();
    			worker.init(intAdmin, serviceConfiguration, serviceName);    			
    		} else {
    			String msg = intres.getLocalizedMessage("services.errorworkerconfig", "null", serviceName);
    			log.error(msg);
    		}
		} catch (Exception e) {						
			String msg = intres.getLocalizedMessage("services.errorworkerconfig", serviceConfiguration.getWorkerClassPath(), serviceName);
			log.error(msg,e);
		}    	
		return worker;
	}

    /**
     * Adds a Service to the database.
     *
     * @throws ServiceExistsException if  service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void addService(Admin admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ")");
    	}
        addService(admin,findFreeServiceId().intValue(),name,serviceConfiguration);
        log.trace("<addService()");
    }

    /**
     * Adds a service to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws ServiceExistsException if service already exists.
     * @ejb.interface-method view-type="both"
     */
    public void addService(Admin admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ", id: " + id + ")");
    	}
        boolean success = false;
        if (isAuthorizedToEditService(admin,serviceConfiguration)) {
        	if (ServiceData.findByName(entityManager, name) == null) {
        		if (ServiceData.findById(entityManager, id) == null) {
        			try {
        				entityManager.persist(new ServiceData(new Integer(id), name, serviceConfiguration));
        				success = true;
        			} catch (Exception e) {
        				log.error("Unexpected error creating new service: ", e);
        			}
        		}
        	}
        	if (success){
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceadded", name));
        	} else {
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.erroraddingservice", name));
        		throw new ServiceExistsException();
        	}
        } else {
        	logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoadd", name));
        }
        log.trace("<addService()");
    }

    /**
     * Updates service configuration, but does not re-set the timer
     * 
     * @param noLogging if true no logging (to the database will be done
     *
     * @ejb.interface-method view-type="both"
     */
    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging) {
    	if (log.isTraceEnabled()) {
            log.trace(">changeService(name: " + name + ")");
    	}
        boolean success = false;
        if(isAuthorizedToEditService(admin,serviceConfiguration)){
        	ServiceData htp = ServiceData.findByName(entityManager, name);
        	if (htp != null) {
        		htp.setServiceConfiguration(serviceConfiguration);
        		success = true;
        	} else {
        		log.error("Can not find service to change: "+name);
        	}
        	if (success) {
        		String msg = intres.getLocalizedMessage("services.serviceedited", name);
        		if (!noLogging) {
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, msg);
        		} else {
            		log.info(msg);
        		}
        	} else {
        		String msg = intres.getLocalizedMessage("services.serviceedited", name);
        		log.error(msg);
        		if (!noLogging) {
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, msg);
        		} else {
            		log.error(msg);        			
        		}
        	}
        }else{
        	String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
    		if (!noLogging) {
    			logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
    		} else {
            	log.error(msg);    			
    		}
        }      
        log.trace("<changeService()");
    }

    /**
     * Adds a service with the same content as the original.
     *
     * @throws ServiceExistsException if service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void cloneService(Admin admin, String oldname, String newname) throws ServiceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">cloneService(name: " + oldname + ")");
    	}
        ServiceConfiguration servicedata = null;
        ServiceData htp = ServiceData.findByName(entityManager, oldname);
        if (htp == null) {
        	String msg = "Error cloning service: No such service found.";
            log.error(msg);
            throw new EJBException(msg);
        }
        try {
        	servicedata = (ServiceConfiguration) htp.getServiceConfiguration().clone();
        	if(isAuthorizedToEditService(admin,servicedata)){                   		
        		try {
        			addService(admin, newname, servicedata);
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicecloned", newname,oldname));
        		} catch (ServiceExistsException f) {
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorcloningservice", newname, oldname));
        			throw f;
        		}        		
        	}else{
        		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
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
    public boolean removeService(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeService(name: " + name + ")");
    	}
        boolean retval = false;
        try {
        	ServiceData htp = ServiceData.findByName(entityManager, name);
        	if (htp == null) {
        		throw new FinderException("Cannot find service " + name);
        	}
        	ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
        	if(isAuthorizedToEditService(admin,serviceConfiguration)){        	        		
        		IWorker worker = getWorker(serviceConfiguration, name);
        		if(worker != null){
        			cancelTimer(htp.getId());
        		}
        		entityManager.remove(htp);
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceremoved", name));
        		retval = true;
        	}else{
        		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", name));
        	}
        } catch (Exception e) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorremovingservice", name), e);
        }
        log.trace("<removeService)");
        return retval;
    }

	public void cancelTimer(Integer id){
		  Collection<Timer> timers = sessionContext.getTimerService().getTimers();
		  Iterator<Timer> iter = timers.iterator();
		  while(iter.hasNext()){
			  try {
				  Timer next = iter.next();
				  if(id.equals(next.getInfo())){
					  next.cancel();
				  }
			  } catch (Exception e) {
				  // EJB 2.1 only?: We need to catch this because Weblogic 10 throws an exception if we
				  // have not scheduled this timer, so we don't have anything to cancel.
				  // Only weblogic though...
				  log.info("Caught exception canceling timer: "+e.getMessage());
			  }
		  }
	}

    /**
     * Adds a timer to the bean, and cancels all existing timeouts for this id.
     *
     * @param id the id of the timer
     * @ejb.interface-method view-type="both"
     */
	public void addTimer(long interval, Integer id){
		// Cancel old timers before adding new one
		cancelTimer(id);
		sessionContext.getTimerService().createTimer(interval, id);
	}

	/**
     * Renames a service
     *
     * @throws ServiceExistsException if service already exists.
     * @ejb.interface-method view-type="both"
     */
    public void renameService(Admin admin, String oldname, String newname) throws ServiceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">renameService(from " + oldname + " to " + newname + ")");
    	}
        boolean success = false;
        if (ServiceData.findByName(entityManager, newname) == null) {
        	ServiceData htp = ServiceData.findByName(entityManager, oldname);
        	if (htp != null) {
            	if (isAuthorizedToEditService(admin, htp.getServiceConfiguration())) {
                    htp.setName(newname);
                    success = true;
              	} else {
              		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
              	}
        	}
        }
        if (success){
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicerenamed", oldname, newname));
        } else {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorrenamingservice", oldname, newname));
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
    public Collection getAuthorizedVisibleServiceIds(Admin admin) {
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
     * Method creating a hashmap mapping service id (Integer) to service name (String).
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public HashMap getServiceIdToNameMap(Admin admin) {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<ServiceData> result = ServiceData.findAll(entityManager);
        Iterator<ServiceData> i = result.iterator();
        while (i.hasNext()) {
        	ServiceData next = i.next();
            returnval.put(next.getId(), next.getName());
        }
        return returnval;
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
    		log.trace(">getService: "+name);
    	}
    	ServiceConfiguration returnval = null;
    	ServiceData serviceData = ServiceData.findByName(entityManager, name);
    	if (serviceData != null) {
    		returnval = serviceData.getServiceConfiguration();
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<getService: "+name);
    	}
        return returnval;
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
    		log.trace(">getServiceConfiguration: "+id);
    	}
    	ServiceConfiguration returnval = null;
        try {            
        	ServiceData serviceData = ServiceData.findById(entityManager, id);
        	if (serviceData != null) {
        		returnval = serviceData.getServiceConfiguration();
        	} else {
            	if (log.isDebugEnabled()) {
            		log.debug("Returnval is null for service id: "+id);
            	}
        	}
        } catch (Exception e) {
            // return null if we cant find it, if it is not due to underlying database error
        	log.debug("Got an Exception for service with id "+ id + ": "+e.getMessage());
        	// If we don't re-throw here it will be treated as the service id does not exist
        	// and the service will not be rescheduled to run.
       		throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<getServiceConfiguration: "+id);
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
        ServiceData serviceData = ServiceData.findByName(entityManager, name);
        if (serviceData != null) {
        	returnval = serviceData.getId();
        }
        return returnval;
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
        ServiceData serviceData = ServiceData.findById(entityManager, id);
        if (serviceData != null) {
        	returnval = serviceData.getName();
        }
        log.trace("<getServiceName()");
        return returnval;
    }

    /**
     * Activates the timer for a named service. The service must already be previously added.
     *
     * @param admin The administrator performing the action
     * @param name the name of the service for which to activate the timer
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void activateServiceTimer(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
        	log.trace(">activateServiceTimer(name: " + name + ")");
    	}
    	ServiceData htp = ServiceData.findByName(entityManager, name);
    	if (htp != null) {
    		ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
    		if(isAuthorizedToEditService(admin,serviceConfiguration)){
    			IWorker worker = getWorker(serviceConfiguration, name);
    			if(worker != null){
    				cancelTimer(htp.getId());
    				if(serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){
    					addTimer(worker.getNextInterval() *1000, htp.getId());
    				}
    			}
    		}else{
    			logSession.log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoedit", name));
    		}
    	} else {
    		log.error("Can not find service: "+name);
    	}
    	log.trace("<activateServiceTimer()");
    }

    /**
     * Method to check if an admin is authorized to edit a service
     * The following checks are performed.
     * 
     * 1. Deny If the service is hidden and the admin is internal EJBCA
     * 2. Allow If the admin is an super administrator
     * 3. Deny all other
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
    		if(authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
    			return true;
    		}
    	} catch (AuthorizationDeniedException e) {
    	}
		return false;
	}

    private Integer findFreeServiceId() {
    	Random ran = (new Random((new Date()).getTime()));
    	int id = ran.nextInt();
    	boolean foundfree = false;
    	while (!foundfree) {
    		if (id > 1) {
    			if (ServiceData.findById(entityManager, id) == null) {
    				foundfree = true;
    			}
    		}
    		id = ran.nextInt();
    	}
        return new Integer(id);
    }
}
