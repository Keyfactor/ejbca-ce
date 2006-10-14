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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Timer;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExistsException;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
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
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 *  @jonas.bean ejb-name="ServiceSession"
 */
public class LocalServiceSessionBean extends BaseSessionBean implements javax.ejb.TimedObject {

    /**
     * The local home interface of service data source entity bean.
     */
    private transient ServiceDataLocalHome servicehome = null;

    /**
     * The local interface of authorization session bean
     */
    private transient IAuthorizationSessionLocal authorizationsession = null;

    /**
     * The remote interface of  log session bean
     */
    private transient ILogSessionLocal logsession = null;
    
    /**
     * The internal resources instance
     */
    private static InternalResources intres = InternalResources.getInstance(); 


    /**
     * The administrator that the services should be runned as.
     */
    Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {    	    
    	
    }
    
    

    /**
     * Method implemented from the TimerObject and is the main method of this
     * session bean. It calls the work object for each object.
     * 
     * @ejb.transaction type="Supports"
     * @param timer
     */
	public void ejbTimeout(Timer timer) {
		Integer timerInfo = (Integer) timer.getInfo();		
			try {
					ServiceDataLocal serviceData = getServiceDataHome().findByPrimaryKey(timerInfo);
					IWorker worker = getWorker(serviceData.getServiceConfiguration(),serviceData.getName());
					try{
						if(serviceData.getServiceConfiguration().isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){
							worker.work();			  
							getSessionContext().getTimerService().createTimer(worker.getNextInterval()*1000, timerInfo);
							getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecuted", serviceData.getName()));
						}
					}catch (ServiceExecutionFailedException e) {
						getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecutionfailed", serviceData.getName()));
					}
			} catch (FinderException e) {
				getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicenotfound", timerInfo));
			} 
		
	}    

    /**
     * Loads and activates all the services from database that are active
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
	public void load(){
    	// Get all services
    	try {
    		Collection currentTimers = getSessionContext().getTimerService().getTimers();
    		Iterator iter = currentTimers.iterator();
    		HashSet existingTimers = new HashSet();
    		while(iter.hasNext()){
    			Timer timer = (Timer) iter.next();
    			existingTimers.add(timer.getInfo());    			
    		}
    		
			Collection allServices = getServiceDataHome().findAll();
			iter = allServices.iterator();
			while(iter.hasNext()){
				ServiceDataLocal dataLocal = (ServiceDataLocal) iter.next();
				if(!existingTimers.contains(dataLocal.getId())){
					IWorker worker = getWorker(dataLocal.getServiceConfiguration(), dataLocal.getName());
					if(worker != null && dataLocal.getServiceConfiguration().isActive()  && worker.getNextInterval() != IInterval.DONT_EXECUTE){
					  getSessionContext().getTimerService().createTimer((worker.getNextInterval()) *1000, dataLocal.getId());
					}
				}
			}
			
		} catch (FinderException e) {
			log.debug("Error fetching services",e);
		}
	}
	
    /**
     * Cancels all existing timers a unload
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
	public void unload(){
		// Get all servicess
		Collection currentTimers = getSessionContext().getTimerService().getTimers();
		Iterator iter = currentTimers.iterator();
		while(iter.hasNext()){
			Timer timer = (Timer) iter.next();			
			timer.cancel(); 			
		}
	}

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
			worker = (IWorker) this.getClass().getClassLoader().loadClass(serviceConfiguration.getWorkerClassPath()).newInstance();
			worker.init(intAdmin, serviceConfiguration, serviceName);
		} catch (Exception e) {						
			log.error("Worker is missconfigured, check the classpath",e);
		}    	
    	
		return worker;
	}



	/**
     * Gets connection to log session bean
     *
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession


    /**
     * Gets connection to service data bean
     *
     * @return ServiceDataLocalHome
     */
    private ServiceDataLocalHome getServiceDataHome() {
        if (servicehome == null) {                
        	servicehome = (ServiceDataLocalHome) getLocator().getLocalHome(ServiceDataLocalHome.COMP_NAME); 
        }
        return servicehome;
    } //getServiceDataHome

    /**
     * Gets connection to authorization session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = authorizationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession

    /**
     * Adds a Service to the database.
     *
     * @throws ServiceExistsException if  service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addService(Admin admin, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        debug(">addService(name: " + name + ")");
        addService(admin,findFreeServiceId().intValue(),name,serviceConfiguration);
        debug("<addService()");
    } // addService


    /**
     * Adds a service to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws ServiceExistsException if service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addService(Admin admin, int id, String name, ServiceConfiguration serviceConfiguration) throws ServiceExistsException {
        debug(">addService(name: " + name + ", id: " + id + ")");
        boolean success = false;
        if(isAuthorizedToEditService(admin,serviceConfiguration)){
        	try {
        		getServiceDataHome().findByName(name);
        	} catch (FinderException e) {
        		try {
        			getServiceDataHome().findByPrimaryKey(new Integer(id));
        		} catch (FinderException f) {
        			try {
        				getServiceDataHome().create(new Integer(id), name, serviceConfiguration);        				
        				IWorker worker = getWorker(serviceConfiguration, name);
        				if(worker != null){
        					if(serviceConfiguration.isActive()  && worker.getNextInterval() != IInterval.DONT_EXECUTE){
        				        getSessionContext().getTimerService().createTimer(worker.getNextInterval() * 1000, new Integer(id));
        					}
        					success = true;
        				}
        				
        			} catch (CreateException g) {
        				error("Unexpected error creating new service: ", g);
        			}
        		}
        	}
        	if (success){
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceadded", name));
        	}else{
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.erroraddingservice", name));
        	}
        	if (!success)
        		throw new ServiceExistsException();
        }else{
        	getLogSession().log(admin, admin.getCaId(),LogEntry.MODULE_SERVICES,new Date(),null,null,LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoadd", name));
        }
        debug("<addService()");
    } // addService

    /**
     * Updates service configuration
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration) {
        debug(">changeService(name: " + name + ")");
        boolean success = false;
        if(isAuthorizedToEditService(admin,serviceConfiguration)){
        	try {
        		ServiceDataLocal htp = getServiceDataHome().findByName(name);
        		htp.setServiceConfiguration(serviceConfiguration);
        		IWorker worker = getWorker(serviceConfiguration, name);
        		if(worker != null){
        		  Collection timers = getSessionContext().getTimerService().getTimers();
        		  Iterator iter = timers.iterator();
        		  while(iter.hasNext()){
        			  Timer next = (Timer) iter.next();
        			  if(htp.getId().equals(next.getInfo())){
        				  next.cancel();
        				  if(serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){
        				    getSessionContext().getTimerService().createTimer(worker.getNextInterval() *1000, htp.getId());
        				  }
        			  }
        		  }
        		  success = true;
        		}
        	} catch (FinderException e) {
        	}
        	
        	if (success){
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceedited", name));
        	}else{
        		getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.erroreditingservice", name));
        	}
        }else{
        	getLogSession().log(admin, admin.getCaId(),LogEntry.MODULE_SERVICES,new Date(),null,null,LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoedit", name));
        }
        
        
        debug("<changeService()");
    } // changeService

    /**
     * Adds a service with the same content as the original.
     *
     * @throws ServiceExistsException if service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void cloneService(Admin admin, String oldname, String newname) throws ServiceExistsException {
        debug(">cloneService(name: " + oldname + ")");
        ServiceConfiguration servicedata = null;
        try {
        	ServiceDataLocal htp = getServiceDataHome().findByName(oldname);
        	servicedata = (ServiceConfiguration) htp.getServiceConfiguration().clone();
        	if(isAuthorizedToEditService(admin,servicedata)){                   		
        		try {
        			addService(admin, newname, servicedata);
        			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicecloned", newname,oldname));
        		} catch (ServiceExistsException f) {
        			getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorcloningservice", newname, oldname));
        			throw f;
        		}        		
        	}else{
        		getLogSession().log(admin, admin.getCaId(),LogEntry.MODULE_SERVICES,new Date(),null,null,LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
        	}            
        } catch (FinderException e) {
            error("Error cloning service: ", e);
            throw new EJBException(e);
        } catch (CloneNotSupportedException e) {
            error("Error cloning service: ", e);
            throw new EJBException(e);
		}

        debug("<cloneService()");
    } // cloneService

    /**
     * Removes a service from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public boolean removeService(Admin admin, String name) {
        debug(">removeService(name: " + name + ")");
        boolean retval = false;
        try {
        	ServiceDataLocal htp = getServiceDataHome().findByName(name);
        	ServiceConfiguration serviceConfiguration = htp.getServiceConfiguration();
        	if(isAuthorizedToEditService(admin,serviceConfiguration)){        	
              htp.remove();        		
        	  IWorker worker = getWorker(serviceConfiguration, name);
        	  if(worker != null){
        		  Collection timers = getSessionContext().getTimerService().getTimers();
        		  Iterator iter = timers.iterator();
        		  while(iter.hasNext()){
        			  Timer next = (Timer) iter.next();
        			  if(htp.getId().equals(next.getInfo())){
        				  next.cancel();        				  
        			  }
        		  }
        	  }
              getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceremoved", name));
              retval = true;
        	}else{
        		getLogSession().log(admin, admin.getCaId(),LogEntry.MODULE_SERVICES,new Date(),null,null,LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", name));
        	}
        } catch (Exception e) {
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorremovingservice", name), e);
        }
        debug("<removeService)");
        
        return retval;
    } // removeService

    /**
     * Renames a service
     *
     * @throws ServiceExistsException if service already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void renameService(Admin admin, String oldname, String newname) throws ServiceExistsException {
        debug(">renameService(from " + oldname + " to " + newname + ")");
        boolean success = false;
        try {
        	getServiceDataHome().findByName(newname);
        } catch (FinderException e) {
            try {
            	ServiceDataLocal htp = getServiceDataHome().findByName(oldname);
            	if(isAuthorizedToEditService(admin,htp.getServiceConfiguration())){
                  htp.setName(newname);
                  success = true;
            	}else{
            		getLogSession().log(admin, admin.getCaId(),LogEntry.MODULE_SERVICES,new Date(),null,null,LogEntry.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
            	}
            } catch (FinderException g) {
            }
        }

        if (success){
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicerenamed", oldname, newname));
        }else{
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorrenamingservice", oldname, newname));
        }
        if (!success)
            throw new ServiceExistsException();
        debug("<renameService()");
    } // renameService

    /**
     * Retrives a Collection of id:s (Integer) to authorized services.
     * Currently is the only check if the superadmin can see them all
     *
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedServiceIds(Admin admin) {
        Collection returnval = new ArrayList();

        // If superadmin return all service
        	try{
              getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
              returnval = getServiceIdToNameMap(admin).keySet();
        	}catch (AuthorizationDeniedException e1) {
              	log.debug("AuthorizationDeniedException: ", e1);
            }
 
        return returnval;
    } // getAuthorizedServiceIds

    /**
     * Method creating a hashmap mapping service id (Integer) to service name (String).
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public HashMap getServiceIdToNameMap(Admin admin) {
        HashMap returnval = new HashMap();
        Collection result = null;

        try {
            result = getServiceDataHome().findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
            	ServiceDataLocal next = (ServiceDataLocal) i.next();
                returnval.put(next.getId(), next.getName());
            }
        } catch (FinderException e) {
        }
        return returnval;
    } // getServiceIdToNameMap


    /**
     * Retrives a named service.
     *
     * @returns the service configuration or null if it doesn't exist.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public ServiceConfiguration getService(Admin admin, String name) {
    	ServiceConfiguration returnval = null;

        try {
        	returnval = (getServiceDataHome().findByName(name)).getServiceConfiguration();            
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } //  getService

    /**
     * Finds a service configuration by id.
     *
     * @returns the service configuration or null if it doesn't exist. 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public ServiceConfiguration getServiceConfiguration(Admin admin, int id) {
    	ServiceConfiguration returnval = null;

        try {            
        	returnval = (getServiceDataHome().findByPrimaryKey(new Integer(id))).getServiceConfiguration();                      
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } // getServiceConfiguration



    /**
     * Returns a service id, given it's service name
     *
     * @return the id or 0 if the service cannot be found.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public int getServiceId(Admin admin, String name) {
        int returnval = 0;

        try {
            Integer id = (getServiceDataHome().findByName(name)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    } // getServiceId

    /**
     * Returns a Service name given its id.
     *
     * @return the name or null if id doesnt exists
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public String getServiceName(Admin admin, int id) {
        debug(">getServiceName(id: " + id + ")");
        String returnval = null;
        ServiceDataLocal htp = null;
        try {
            htp = getServiceDataHome().findByPrimaryKey(new Integer(id));
            if (htp != null) {
                returnval = htp.getName();
            }
        } catch (FinderException e) {
        }

        debug("<getServiceName()");
        return returnval;
    } // getServiceName
    
    
    
    /**
     * Method to check if an admin is authorized to edit a service
     * The following checks are performed.
     * 
     * 1. If the admin is an super administrator
     * 
     * @return true if the administrator is authorized
     */
    private boolean isAuthorizedToEditService(Admin admin, ServiceConfiguration serviceConfiguraion) {
    	try {
    		if(getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_SUPERADMINISTRATOR)){
    			return true;
    		}
    	} catch (AuthorizationDeniedException e) {}
    	
		return false;
	}


    private Integer findFreeServiceId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1)
                	getServiceDataHome().findByPrimaryKey(new Integer(id));
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreeServiceId









} // LocalServiceSessionBean
