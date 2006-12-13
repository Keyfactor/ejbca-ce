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
package org.ejbca.core.model.services;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.intervals.DummyInterval;

/**
 * Abstract base class that initializes the worker and its interval and action.
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: BaseWorker.java,v 1.6 2006-12-13 10:35:09 anatom Exp $
 */
public abstract class BaseWorker extends BaseServiceComponent implements IWorker {

	private static final Logger log = Logger.getLogger(BaseWorker.class);
	
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    protected Properties properties = null;
    protected String serviceName = null;
    private IAction action = null;
    private IInterval interval = null;
    
    private Admin admin = null;

	/**
	 * @see org.ejbca.core.model.services.IWorker#init(org.ejbca.core.model.services.ServiceConfiguration, java.lang.String)
	 */
	public void init(Admin admin, ServiceConfiguration serviceConfiguration,
			String serviceName) {
		this.admin = admin;
		this.serviceName = serviceName;
		this.properties = serviceConfiguration.getWorkerProperties();
		
		String actionClassPath = serviceConfiguration.getActionClassPath();
		if(actionClassPath != null){
			try {
				action = (IAction) this.getClass().getClassLoader().loadClass(actionClassPath).newInstance();
				action.init(serviceConfiguration.getActionProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("services.erroractionclasspath", serviceName);
				log.error(msg,e);
			}       
		}else{
			log.debug("Warning no action class i defined for the service " + serviceName);
		}
		
		String intervalClassPath = serviceConfiguration.getIntervalClassPath();
		if(intervalClassPath != null){
			try {
				interval = (IInterval) this.getClass().getClassLoader().loadClass(intervalClassPath).newInstance();
				interval.init(serviceConfiguration.getIntervalProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
				log.error(msg,e);
			}       
		}else{
			String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
			log.error(msg);
		}
		
		if(interval == null){
			interval = new DummyInterval();
		}

	}

	
	/**
	 * @see org.ejbca.core.model.services.IWorker#getNextInterval()
	 */
	public long getNextInterval() {		
		return interval.getTimeToExecution();
	}
	
	protected IAction getAction(){
		if(action == null){
			String msg = intres.getLocalizedMessage("services.erroractionclasspath", serviceName);
			log.error(msg);
		}
		return action;
	}
	
	/**
	 * Returns the admin that should be used for other calls.
	 */
	protected Admin getAdmin(){
		return admin;
	}
	

}
