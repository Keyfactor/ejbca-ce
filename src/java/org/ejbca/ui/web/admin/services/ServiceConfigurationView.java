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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class resposible for converting the data between the GUI and a
 * SystemConfiguration VO
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: ServiceConfigurationView.java,v 1.2 2006-10-14 05:01:48 herrvendil Exp $
 */
public class ServiceConfigurationView {
	
	private WorkerType workerType;
	private ActionType actionType;
	private IntervalType intervalType;
	
    private String selectedWorker;
    private String selectedInterval;
    private String selectedAction;
    
    private ServiceTypeManager typeManager;
	
	private boolean active = false;
	private String description = "";
	
	public ServiceConfigurationView(ServiceConfiguration serviceConfiguration) throws IOException {
		
		typeManager = new ServiceTypeManager();
		
		WorkerType workerType = (WorkerType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getWorkerClassPath());
		if(workerType == null){
		   workerType = new CustomWorkerType();
		  ((CustomWorkerType) workerType).setClassPath(serviceConfiguration.getWorkerClassPath());
		}		
		workerType.setProperties(serviceConfiguration.getWorkerProperties());
	    setWorkerType(workerType);
	    selectedWorker = workerType.getName();			
		
		IntervalType intervalType = (IntervalType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getIntervalClassPath());
		if(intervalType == null){
		  intervalType = new CustomIntervalType();
		  ((CustomIntervalType) intervalType).setClassPath(serviceConfiguration.getIntervalClassPath());
		}		
		intervalType.setProperties(serviceConfiguration.getIntervalProperties());
		setIntervalType(intervalType);
		selectedInterval = intervalType.getName();
		
		ActionType actionType = (ActionType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getActionClassPath());
		if(actionType == null){
		  actionType = new CustomActionType();
		  ((CustomActionType) actionType).setClassPath(serviceConfiguration.getActionClassPath());
		}		
		actionType.setProperties(serviceConfiguration.getActionProperties());
	    setActionType(actionType);
		selectedAction = actionType.getName();
	      
		
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
		
		
		if(selectedInterval != null &&!getAvailableIntervals().contains(selectedInterval)){				
			setSelectedInterval((String) workerType.getCompatibleIntervalTypeNames().iterator().next());
			setIntervalType((IntervalType) typeManager.getServiceTypeByName(getSelectedInterval()));
		}
		
		if(selectedAction != null && !getAvailableActions().contains(selectedAction)){
			setSelectedAction((String) workerType.getCompatibleActionTypeNames().iterator().next());
			setActionType((ActionType) typeManager.getServiceTypeByName(getSelectedAction()));
		}
	}
	
	/**
	 * @return the selectedAction
	 */
	public String getSelectedAction() {
		return selectedAction;
	}

	/**
	 * @param selectedAction the selectedAction to set
	 */
	public void setSelectedAction(String selectedAction) {
		this.selectedAction = selectedAction;
	}

	/**
	 * @return the selectedInterval
	 */
	public String getSelectedInterval() {
		return selectedInterval;
	}

	/**
	 * @param selectedInterval the selectedInterval to set
	 */
	public void setSelectedInterval(String selectedInterval) {
		this.selectedInterval = selectedInterval;
	}

	/**
	 * @return the selectedWorker
	 */
	public String getSelectedWorker() {
		return selectedWorker;
	}

	/**
	 * @param selectedWorker the selectedWorker to set
	 */
	public void setSelectedWorker(String selectedWorker) {
		this.selectedWorker = selectedWorker;
	}	
	
	public List getAvailableWorkers(){
		ArrayList retval = new ArrayList();
		Collection available = typeManager.getAvailableWorkerTypes();
		Iterator iter = available.iterator();
		while(iter.hasNext()){
			ServiceType next = (ServiceType) iter.next();
			String label = next.getName();
			if(next.isTranslatable()){
				label = (String) EjbcaJSFHelper.getBean().getText().get(next.getName());
			}
			retval.add(new SelectItem(next.getName(),label));
		}
		
		return retval;
	}
	
	public List getAvailableIntervals(){
		ArrayList retval = new ArrayList();
		WorkerType currentWorkerType = (WorkerType) typeManager.getServiceTypeByName(selectedWorker);
		Iterator iter = currentWorkerType.getCompatibleIntervalTypeNames().iterator();
		while(iter.hasNext()){
			String name = (String) iter.next();
			ServiceType next = typeManager.getServiceTypeByName(name);
			String label = name;
			if(next.isTranslatable()){
				label = (String) EjbcaJSFHelper.getBean().getText().get(name);
			}
			
			retval.add(new SelectItem(name,label));
		}
		
		
		return retval;
	}
	
	public List getAvailableActions(){
		ArrayList retval = new ArrayList();
		WorkerType currentWorkerType = (WorkerType) typeManager.getServiceTypeByName(selectedWorker);
		Iterator iter = currentWorkerType.getCompatibleActionTypeNames().iterator();
		while(iter.hasNext()){
			String name = (String) iter.next();
			ServiceType next = typeManager.getServiceTypeByName(name);
			String label = name;
			if(next.isTranslatable()){
				label = (String) EjbcaJSFHelper.getBean().getText().get(name);
			}
			retval.add(new SelectItem(name,label));
		}		
		return retval;
	}
	
	/** returns this sessions service type manager */
	public ServiceTypeManager getServiceTypeManager(){
		return typeManager;
	}
	
	
	


}
