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
package org.ejbca.ui.web.admin.services;



import java.io.IOException;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class resposible for converting the data between the GUI and a
 * SystemConfiguration VO
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: ServiceConfigurationView.java,v 1.1 2006-10-01 17:46:48 herrvendil Exp $
 */
public class ServiceConfigurationView {
	
	private WorkerType workerType;
	private ActionType actionType;
	private IntervalType intervalType;
	
	private boolean active = false;
	private String description = "";
	
	public ServiceConfigurationView(ServiceConfiguration serviceConfiguration) throws IOException {
		IntervalType intervalType = (IntervalType) ServiceTypeManager.getServiceTypeByClassPath(serviceConfiguration.getIntervalClassPath());
		if(intervalType == null){
		  intervalType = new CustomIntervalType();
		  ((CustomIntervalType) intervalType).setClassPath(serviceConfiguration.getIntervalClassPath());
		}		
		intervalType.setProperties(serviceConfiguration.getIntervalProperties());
		setIntervalType(intervalType);
		
		ActionType actionType = (ActionType) ServiceTypeManager.getServiceTypeByClassPath(serviceConfiguration.getActionClassPath());
		if(actionType == null){
		  actionType = new CustomActionType();
		  ((CustomActionType) actionType).setClassPath(serviceConfiguration.getActionClassPath());
		}		
		actionType.setProperties(serviceConfiguration.getActionProperties());
	    setActionType(actionType);
		
		WorkerType workerType = (WorkerType) ServiceTypeManager.getServiceTypeByClassPath(serviceConfiguration.getWorkerClassPath());
		if(workerType == null){
		   workerType = new CustomWorkerType();
		  ((CustomWorkerType) workerType).setClassPath(serviceConfiguration.getWorkerClassPath());
		}		
		workerType.setProperties(serviceConfiguration.getWorkerProperties());
	    setWorkerType(workerType);
		
		setDescription(serviceConfiguration.getDescription());
		setActive(serviceConfiguration.isActive());
	}
	
	/**
	 * Method that populates a service configuration from a
	 * GUI data.
	 */
	public ServiceConfiguration getServiceConfiguration() throws IOException{
		ServiceConfiguration retval = new ServiceConfiguration();
		retval.setActive(isActive());
		retval.setDescription(getDescription());
		retval.setActionClassPath(getActionType().getClassPath());
		retval.setActionProperties(getActionType().getProperties()); 
		retval.setIntervalClassPath(getIntervalType().getClassPath());
		retval.setIntervalProperties(getIntervalType().getProperties());
		retval.setWorkerClassPath(getWorkerType().getClassPath());
		retval.setWorkerProperties(getWorkerType().getProperties());
		return retval;
	}

	/**
	 * @return the actionType
	 */
	public ActionType getActionType() {
		return actionType;
	}

	/**
	 * @param actionType the actionType to set
	 */
	public void setActionType(ActionType actionType) {
		this.actionType = actionType;
	}

	/**
	 * @return the active
	 */
	public boolean isActive() {
		return active;
	}

	/**
	 * @param active the active to set
	 */
	public void setActive(boolean active) {
		this.active = active;
	}

	/**
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * @param description the description to set
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * @return the intervalType
	 */
	public IntervalType getIntervalType() {
		return intervalType;
	}

	/**
	 * @param intervalType the intervalType to set
	 */
	public void setIntervalType(IntervalType intervalType) {
		this.intervalType = intervalType;
	}

	/**
	 * @return the workerType
	 */
	public WorkerType getWorkerType() {
		return workerType;
	}

	/**
	 * @param workerType the workerType to set
	 */
	public void setWorkerType(WorkerType workerType) {
		this.workerType = workerType;
	}
	
	

}
