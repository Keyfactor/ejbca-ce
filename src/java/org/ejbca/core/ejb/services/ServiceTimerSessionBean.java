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
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.Timer;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExecutionFailedException;


/**
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean description="Timed Object Session bean running the services"
 *   display-name="ServiceTimerSessionSB"
 *   name="ServiceTimerSession"
 *   jndi-name="ServiceTimerSession"
 *   local-jndi-name="ServiceTimerSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Bean"
 *
 * @weblogic.enable-call-by-reference True
 * 
 * @ejb.transaction type="Supports"
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *   
 *
 * @ejb.env-entry
 *   description="Defines the JNDI name of the mail service used"
 *   name="MailJNDIName"
 *   type="java.lang.String"
 *   value="${mail.jndi-name}"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.services.IServiceTimerSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.services.IServiceTimerSessionLocal"
 *   remote-class="org.ejbca.core.ejb.services.IServiceTimerSessionRemote"
 *
 * @ejb.ejb-external-ref description="The Service session bean"
 *   view-type="local"
 *   ref-name="ejb/ServiceSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.services.IServiceSessionLocalHome"
 *   business="org.ejbca.core.ejb.services.IServiceSessionLocal"
 *   link="ServiceSession"
 *
 * @ejb.ejb-external-ref description="The Certificate entity bean used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.store.CertificateDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.CertificateDataLocal"
 *   link="CertificateData"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref description="The User Admin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
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
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref description="The CRL Create bean"
 *   view-type="local"
 *   ref-name="ejb/CreateCRLSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *   link="CreateCRLSession"
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
 *  @jonas.bean ejb-name="ServiceTimerSession"
 *  
 *  @version $Id$
 */
public class ServiceTimerSessionBean extends BaseSessionBean implements javax.ejb.TimedObject {



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
     * Constant indicating the Id of the "service loader" service.
     * Used in a clustered environment to perodically load available
     * services
     */
    private static final Integer SERVICELOADER_ID = Integer.valueOf(0);
    
    private static final long SERVICELOADER_PERIOD = 5 * 60 * 1000;

    /**
     * Method implemented from the TimerObject and is the main method of this
     * session bean. It calls the work object for each object.
     * 
     * @param timer
     */
	public void ejbTimeout(Timer timer) {
		debug(">ejbTimeout");    		
		Integer timerInfo = (Integer) timer.getInfo();
		if(timerInfo.equals(SERVICELOADER_ID)){
			log.debug("Running the internal Service loader.");
			load();
		}else{		
			ServiceConfiguration serviceData = null;
			IWorker worker = null;
			String serviceName = null;
			boolean run = false;
			try{
				serviceData = getServiceSession().getServiceConfiguration(intAdmin, timerInfo.intValue());
				if(serviceData != null){
					serviceName = getServiceSession().getServiceName(intAdmin, timerInfo.intValue());
					worker = getWorker(serviceData,serviceName);
					run = checkAndUpdateServiceTimeout(worker.getNextInterval(), timerInfo, serviceData, serviceName);
				}
			} catch (Exception e) {
			    // We need to catch wide here in order to continue even if there is some error
				log.error(e);
			}
			if(run){
				if(serviceData != null){
					try{
						if(serviceData.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){				
							worker.work();			  							
							getLogSession().log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecuted", serviceName));
						}
					}catch (ServiceExecutionFailedException e) {
						getLogSession().log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecutionfailed", serviceName));
					}
				} else {
					getLogSession().log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicenotfound", timerInfo));
				} 
			}else{
				getLogSession().log(intAdmin, intAdmin.getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), null, null, LogConstants.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicerunonothernode", timerInfo));
			}
		}
		debug("<ejbTimeout");		
	}    
    /**
     * Internal method should not be called from external classes, method is public to get automatic transaction handling.
     * 
     * This method need "RequiresNew" transaction handling, because we want to make sure that the timer
     * runs the next time even if the execution fails.
     * 
     * @ejb.transaction type="RequiresNew"
     */
	public boolean checkAndUpdateServiceTimeout(long nextInterval, int timerInfo, ServiceConfiguration serviceData, String serviceName) {
		boolean ret = false;
		// Add a random delay within 30 seconds to the interval, just to make sure nodes in a cluster is
		// not scheduled to run on the exact same second
		Random rand = new Random();
		int i = rand.nextInt(30000);
		getSessionContext().getTimerService().createTimer((nextInterval*1000+i), timerInfo);
		Date nextRunDate = serviceData.getNextRunTimestamp();
		Date currentDate = new Date();
		// Check if the current date is after when the service should run.
		// If a service on another cluster node has updated this timestamp already, then it will return false and
		// this service will not run.
		// This is a semaphor so that services in a cluster only runs on one node and don't compete with each other.
		if(currentDate.after(nextRunDate)){
			nextRunDate = new Date(currentDate.getTime() + nextInterval);
			serviceData.setNextRunTimestamp(nextRunDate);
			getServiceSession().changeService(intAdmin, serviceName, serviceData); 
			ret=true;
		}		
		return ret;
	}

    /**
     * Loads and activates all the services from database that are active
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void load(){
		// Get all services

		Collection currentTimers = getSessionContext().getTimerService().getTimers();
		Iterator iter = currentTimers.iterator();
		HashSet existingTimers = new HashSet();
		while(iter.hasNext()){
			Timer timer = (Timer) iter.next();
			try {
				Serializable info = timer.getInfo();
				existingTimers.add(info);    			
			} catch (Throwable e) {
				// We need this try because weblogic seems to suck...
				log.debug("Error invoking timer.getInfo(): ", e);
			}
		}

		HashMap idToNameMap = getServiceSession().getServiceIdToNameMap(intAdmin);
		Collection allServices = idToNameMap.keySet();
		iter = allServices.iterator();
		while(iter.hasNext()){
			Integer id = (Integer) iter.next();
			ServiceConfiguration serviceConfiguration = getServiceSession().getServiceConfiguration(intAdmin, id.intValue());
			if(!existingTimers.contains(id)){
				IWorker worker = getWorker(serviceConfiguration, (String) idToNameMap.get(id));
				if(worker != null && serviceConfiguration.isActive()  && worker.getNextInterval() != IInterval.DONT_EXECUTE){
					getSessionContext().getTimerService().createTimer((worker.getNextInterval()) *1000, id);
				}
			}
		}

		if(!existingTimers.contains(SERVICELOADER_ID)){
			// load the service timer
			getSessionContext().getTimerService().createTimer(SERVICELOADER_PERIOD, SERVICELOADER_ID);
		}
	}
	
    /**
     * Cancels all existing timers a unload
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void unload(){
		// Get all servicess
		Collection currentTimers = getSessionContext().getTimerService().getTimers();
		Iterator iter = currentTimers.iterator();
		while(iter.hasNext()){
			try {
				Timer timer = (Timer) iter.next();			
				timer.cancel(); 							
			} catch (Exception e) {
				// We need to catch this because Weblogic 10 throws an exception if we
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
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void addTimer(long interval, Integer id){
		// Cancel old timers before adding new one
		cancelTimer(id);
		getSessionContext().getTimerService().createTimer(interval, id);
	}
	
    /**
     * cancels a timer with the given Id
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void cancelTimer(Integer id){
		  Collection timers = getSessionContext().getTimerService().getTimers();
		  Iterator iter = timers.iterator();
		  while(iter.hasNext()){
			  try {
				  Timer next = (Timer) iter.next();
				  if(id.equals(next.getInfo())){
					  next.cancel();
				  }
			  } catch (Exception e) {
				  // We need to catch this because Weblogic 10 throws an exception if we
				  // have not scheduled this timer, so we don't have anything to cancel.
				  // Only weblogic though...
				  log.info("Caught exception canceling timer: "+e.getMessage());
			  }
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
    		String clazz = serviceConfiguration.getWorkerClassPath();
    		if (StringUtils.isNotEmpty(clazz)) {
    			worker = (IWorker) this.getClass().getClassLoader().loadClass(clazz).newInstance();
    			worker.init(intAdmin, serviceConfiguration, serviceName);    			
    		} else {
    			log.info("Worker has empty classpath for service "+serviceName);
    		}
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
     * Gets connection a service session, used for timed services
     *
     * @return Connection
     */
    private IServiceSessionLocal getServiceSession() {
    	IServiceSessionLocal servicesession = null;
    	try {
    		IServiceSessionLocalHome servicesessionhome = (IServiceSessionLocalHome) getLocator().getLocalHome(IServiceSessionLocalHome.COMP_NAME);
    		servicesession = servicesessionhome.create();
    	} catch (CreateException e) {
    		throw new EJBException(e);
    	}

        return servicesession ;
    } //getServiceSession 





} // LocalServiceSessionBean
