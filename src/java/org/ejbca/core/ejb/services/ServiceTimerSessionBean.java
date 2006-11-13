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

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.Timer;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;
import javax.transaction.UserTransaction;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
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
 *  @jonas.bean ejb-name="ServiceTimerSession"
 */
public class ServiceTimerSessionBean extends BaseSessionBean implements javax.ejb.TimedObject {



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
     * @param timer
     */
	public void ejbTimeout(Timer timer) {
		Integer timerInfo = (Integer) timer.getInfo();
		
		ServiceConfiguration serviceData = null;
		IWorker worker = null;
		String serviceName = null;
		boolean run = false;
		try{
		  UserTransaction ut = getSessionContext().getUserTransaction();
		  ut.begin();
	      serviceData = getServiceSession().getServiceConfiguration(intAdmin, timerInfo);
	      if(serviceData != null){
	    	  serviceName = getServiceSession().getServiceName(intAdmin, timerInfo.intValue());
		      worker = getWorker(serviceData,serviceName);
	      	  Date nextRunDate = serviceData.getNextRunTimestamp();
	      	  Date currentDate = new Date();
	      	  if(currentDate.after(nextRunDate)){
	      		  nextRunDate = new Date(currentDate.getTime() + worker.getNextInterval());
	      		  serviceData.setNextRunTimestamp(nextRunDate);
	      		  run=true;
	      	  }         	      	  
	      }
	      ut.commit();
		}catch(NotSupportedException e){
			log.error(e);
		} catch (SystemException e) {
			log.error(e);
		} catch (SecurityException e) {
			log.error(e);
		} catch (IllegalStateException e) {
			log.error(e);
		} catch (RollbackException e) {
			log.error(e);
		} catch (HeuristicMixedException e) {
			log.error(e);
		} catch (HeuristicRollbackException e) {
			log.error(e);
		}
	      
		if(run){
			if(serviceData != null){

				try{
					if(serviceData.isActive() && worker.getNextInterval() != IInterval.DONT_EXECUTE){
						getSessionContext().getTimerService().createTimer(worker.getNextInterval()*1000, timerInfo);
						worker.work();			  							
						getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecuted", serviceName));
					}
				}catch (ServiceExecutionFailedException e) {
					getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.serviceexecutionfailed", serviceName));
				}
			} else {
				getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicenotfound", timerInfo));
			} 
		}else{
			getLogSession().log(intAdmin, intAdmin.getCaId(), LogEntry.MODULE_SERVICES, new java.util.Date(), null, null, LogEntry.EVENT_INFO_SERVICEEXECUTED, intres.getLocalizedMessage("services.servicerunonothernode", timerInfo));
		}

	}    

    /**
     * Loads and activates all the services from database that are active
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void load(){
    	// Get all services

    		Collection currentTimers = getSessionContext().getTimerService().getTimers();
    		Iterator iter = currentTimers.iterator();
    		HashSet existingTimers = new HashSet();
    		while(iter.hasNext()){
    			Timer timer = (Timer) iter.next();
    			existingTimers.add(timer.getInfo());    			
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
			

	}
	
    /**
     * Cancels all existing timers a unload
     *
     * @throws EJBException             if a communication or other error occurs.
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
     * Adds a timer to the bean
     *
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
	public void addTimer(long interval, Integer id){
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
			  Timer next = (Timer) iter.next();
			  if(id.equals(next.getInfo())){
				  next.cancel();
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
