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

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
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
public class LocalServiceSessionBean extends BaseSessionBean  {

    /**
     * The local home interface of service data source entity bean.
     */
    private transient ServiceDataLocalHome servicehome = null;
    
    /**
     * The local  interface of service timer session
     */
    private transient IServiceTimerSessionLocal serviceTimerSession = null;
    

    /**
     * The local interface of authorization session bean
     */
    private transient IAuthorizationSessionLocal authorizationsession = null;

    /**
     * The remote interface of  log session bean
     */
    private transient ILogSessionLocal logsession = null;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();


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
    			worker = (IWorker) this.getClass().getClassLoader().loadClass(cp).newInstance();
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
     * Gets connection to service timer session bean
     *
     * @return IServiceTimerSessionLocal
     */
    private IServiceTimerSessionLocal getServiceTimerSession() {
        if (serviceTimerSession == null) {
            try {
                IServiceTimerSessionLocalHome servicetimersessionhome = (IServiceTimerSessionLocalHome) getLocator().getLocalHome(IServiceTimerSessionLocalHome.COMP_NAME);
                serviceTimerSession = servicetimersessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return serviceTimerSession;
    } //getServiceTimerSession
    
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
    	if (log.isTraceEnabled()) {
            log.trace(">addService(name: " + name + ", id: " + id + ")");
    	}
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
        				success = true;
        				
        			} catch (CreateException g) {
        				error("Unexpected error creating new service: ", g);
        			}
        		}
        	}
        	if (success){
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceadded", name));
        	}else{
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.erroraddingservice", name));
        	}
        	if (!success) {
        		throw new ServiceExistsException();
        	}
        }else{
        	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoadd", name));
        }
        log.trace("<addService()");
    } // addService

    /**
     * Updates service configuration, but does not re-set the timer
     * 
     * @param noLogging if true no logging (to the database will be done
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void changeService(Admin admin, String name, ServiceConfiguration serviceConfiguration, boolean noLogging) {
    	if (log.isTraceEnabled()) {
            log.trace(">changeService(name: " + name + ")");
    	}
        boolean success = false;
        if(isAuthorizedToEditService(admin,serviceConfiguration)){
        	try {
        		ServiceDataLocal htp = getServiceDataHome().findByName(name);
        		htp.setServiceConfiguration(serviceConfiguration);
        		success = true;
        	} catch (FinderException e) {
        		error("Can not find service to change: "+name);
        	}
        	
        	if (success){
        		String msg = intres.getLocalizedMessage("services.serviceedited", name);
        		if (!noLogging) {
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, msg);
        		} else {
            		log.info(msg);
        		}
        	}else{
        		String msg = intres.getLocalizedMessage("services.serviceedited", name);
        		log.error(msg);
        		if (!noLogging) {
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, msg);
        		} else {
            		log.error(msg);        			
        		}
        	}
        }else{
        	String msg = intres.getLocalizedMessage("services.notauthorizedtoedit", name);
    		if (!noLogging) {
    			getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
    		} else {
            	log.error(msg);    			
    		}
        }      
        
        log.trace("<changeService()");
    } // changeService

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
        try {
        	ServiceDataLocal htp = getServiceDataHome().findByName(oldname);
        	servicedata = (ServiceConfiguration) htp.serviceConfiguration().clone();
        	if(isAuthorizedToEditService(admin,servicedata)){                   		
        		try {
        			addService(admin, newname, servicedata);
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicecloned", newname,oldname));
        		} catch (ServiceExistsException f) {
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorcloningservice", newname, oldname));
        			throw f;
        		}        		
        	}else{
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
        	}            
        } catch (FinderException e) {
            error("Error cloning service: ", e);
            throw new EJBException(e);
        } catch (CloneNotSupportedException e) {
            error("Error cloning service: ", e);
            throw new EJBException(e);
		}
        log.trace("<cloneService()");
    } // cloneService

    /**
     * Removes a service from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public boolean removeService(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeService(name: " + name + ")");
    	}
        boolean retval = false;
        try {
        	ServiceDataLocal htp = getServiceDataHome().findByName(name);
        	ServiceConfiguration serviceConfiguration = htp.serviceConfiguration();
        	if(isAuthorizedToEditService(admin,serviceConfiguration)){        	        		
        	  IWorker worker = getWorker(serviceConfiguration, name);
        	  if(worker != null){
        		  getServiceTimerSession().cancelTimer(htp.getId());
        	  }
              htp.remove();
              getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.serviceremoved", name));
              retval = true;
        	}else{
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", name));
        	}
        } catch (Exception e) {
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorremovingservice", name), e);
        }
        log.trace("<removeService)");
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
    	if (log.isTraceEnabled()) {
            log.trace(">renameService(from " + oldname + " to " + newname + ")");
    	}
        boolean success = false;
        try {
        	getServiceDataHome().findByName(newname);
        } catch (FinderException e) {
            try {
            	ServiceDataLocal htp = getServiceDataHome().findByName(oldname);
            	if(isAuthorizedToEditService(admin,htp.serviceConfiguration())){
                  htp.setName(newname);
                  success = true;
            	}else{
            		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, intres.getLocalizedMessage("services.notauthorizedtoedit", oldname));
            	}
            } catch (FinderException g) {
            }
        }

        if (success){
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICESEDITED, intres.getLocalizedMessage("services.servicerenamed", oldname, newname));
        }else{
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICESEDITED, intres.getLocalizedMessage("services.errorrenamingservice", oldname, newname));
        }
        if (!success) {
            throw new ServiceExistsException();
        }
        log.trace("<renameService()");
    } // renameService

    /**
     * Retrives a Collection of id:s (Integer) to visible authorized services.
     * Currently is the only check if the superadmin can see them all
     *
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedVisibleServiceIds(Admin admin) {
        Collection allServiceIds = new ArrayList();
        Collection allVisibleServiceIds = new ArrayList();
        // If superadmin return all visible services
        try {
        	getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        	allServiceIds = getServiceIdToNameMap(admin).keySet();
        	Iterator i = allServiceIds.iterator();
        	while (i.hasNext()) {
        		int id = ((Integer) i.next()).intValue();
        		// Remove hidden services here..
        		if (!getServiceConfiguration(admin, id).isHidden()) {
        			allVisibleServiceIds.add(new Integer(id));
        		}
        	}
        } catch (AuthorizationDeniedException e) {
        	log.debug("AuthorizationDeniedException: ", e);
        }
        return allVisibleServiceIds;
    } // getAuthorizedVisibleServiceIds

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
    	if (log.isTraceEnabled()) {
    		log.trace(">getService: "+name);
    	}
    	ServiceConfiguration returnval = null;

        try {
        	returnval = (getServiceDataHome().findByName(name)).serviceConfiguration();            
        } catch (FinderException e) {
            // return null if we cant find it
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<getService: "+name);
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
    	if (log.isTraceEnabled()) {
    		log.trace(">getServiceConfiguration: "+id);
    	}
    	ServiceConfiguration returnval = null;

        try {            
        	returnval = (getServiceDataHome().findByPrimaryKey(new Integer(id))).serviceConfiguration();                      
        } catch (FinderException e) {
            // return null if we cant find it, if it is not due to underlying database error
        	log.debug("Got a FinderException for service with id "+ id + ": "+e.getMessage());
        	// This is a way to try to figure out if it is an underlying database error or if it is simply that
        	// the id does not exist.
        	// If we don't re-throw here it will be treated as the service id does not exist
        	// and the service will not be rescheduled to run.
        	if ((e.getCause() != null) && e.getCause().getClass().getName().contains("SQLException")) {
        		log.debug("Rethrowing EJBException 1.");
        		throw new EJBException("Find failed: ", (Exception)e.getCause());
        	}
        	if ((e.getMessage() != null) && e.getMessage().contains("Find failed")) {
        		log.debug("Rethrowing EJBException 2.");
        		throw new EJBException("Find failed: ", (Exception)e.getCause());
        	}
        }
    	if ( (returnval == null) && (log.isDebugEnabled()) ) {
    		log.debug("Returnval is null for id: "+id);
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<getServiceConfiguration: "+id);
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
    	if (log.isTraceEnabled()) {
            log.trace(">getServiceName(id: " + id + ")");
    	}
        String returnval = null;
        ServiceDataLocal htp = null;
        try {
            htp = getServiceDataHome().findByPrimaryKey(new Integer(id));
            if (htp != null) {
                returnval = htp.getName();
            }
        } catch (FinderException e) {
        }
        log.trace("<getServiceName()");
        return returnval;
    } // getServiceName
    
    
    /**
     * Activates the timer for a named service. The service must alrteady be previously added.
     *
     * @param admin The administrator performing the action
     * @param name the name of the service for which to activate the timer
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public void activateServiceTimer(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
        	log.trace(">activateServiceTimer(name: " + name + ")");
    	}
    	try {
    		ServiceDataLocal htp = getServiceDataHome().findByName(name);
    		ServiceConfiguration serviceConfiguration = htp.serviceConfiguration();
    		if(isAuthorizedToEditService(admin,serviceConfiguration)){
    			IWorker worker = getWorker(serviceConfiguration, name);
    			if(worker != null){
    				getServiceTimerSession().cancelTimer(htp.getId());
    				if(serviceConfiguration.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){
    					getServiceTimerSession().addTimer(worker.getNextInterval() *1000, htp.getId());
    				}
    			}
    		}else{
    			getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_SERVICES,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,intres.getLocalizedMessage("services.notauthorizedtoedit", name));
    		}
    	} catch (FinderException e) {
    		log.error("Can not find service: "+name);
    	}
    	log.trace("<activateServiceTimer()");
    } // getServiceName
    
    
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
    		} if(getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_SUPERADMINISTRATOR)){
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
                if (id > 1) {
                	// Will throw exception if id is not found in the database
                	getServiceDataHome().findByPrimaryKey(new Integer(id));
                }
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreeServiceId


} // LocalServiceSessionBean
