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

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;
import javax.faces.event.ValueChangeEvent;
import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class used to manage the GUI editing of a Service Configuration
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: EditServiceManagedBean.java,v 1.1 2006-10-01 17:46:48 herrvendil Exp $
 */
public class EditServiceManagedBean extends BaseManagedBean {
	
	private ServiceConfigurationView serviceConfigurationView;
	
	private String serviceName = "";
	
    private String selectedWorker;
    private String selectedInterval;
    private String selectedAction;
	
	public EditServiceManagedBean(){
		try {
			setServiceConfiguration(new ServiceConfiguration());
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		setServiceName("TestService");
	}
	
    public static EditServiceManagedBean getBean(){    
    	FacesContext context = FacesContext.getCurrentInstance();    
    	Application app = context.getApplication();    
    	ValueBinding binding = app.createValueBinding("#{editService}");    
    	Object value = binding.getValue(context);    
    	return (EditServiceManagedBean) value;
    }
    
	/**
	 * @return the serviceName
	 */
	public String getServiceName() {
		return serviceName;
	}

	/**
	 * @param serviceName the serviceName to set
	 */
	public void setServiceName(String serviceName) {
		this.serviceName = serviceName;
	}

	/**
	 * @return the serviceConfigurationView
	 */
	public ServiceConfigurationView getServiceConfigurationView() {
		return serviceConfigurationView;
	}
	
	public void setServiceConfiguration(ServiceConfiguration serviceConfiguration) throws IOException{
		this.serviceConfigurationView = new ServiceConfigurationView(serviceConfiguration);
	}

	public String save(){
		System.out.println("Save pressed");
		
		return "listservices";
	}
	
	public String cancel(){
		System.out.println("Cancel pressed");
		return "listservices";
	}
	
	
	/**
	 * Help method used to edit data in the custom worker type.
	 */
	public CustomWorkerType getCustomWorkerType(){
		return (CustomWorkerType) this.serviceConfigurationView.getWorkerType();
	}
	
	/**
	 * Help method used to edit data in the custom action type.
	 */
	public CustomActionType getCustomActionType(){
		return (CustomActionType) this.serviceConfigurationView.getActionType();
	}	
	
	/**
	 * Help method used to edit data in the custom interval type.
	 */
	public CustomIntervalType getCustomIntervalType(){
		return (CustomIntervalType) this.serviceConfigurationView.getIntervalType();
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
		Collection available = ServiceTypeManager.getAvailableWorkerTypes();
		Iterator iter = available.iterator();
		while(iter.hasNext()){
			ServiceType next = (ServiceType) iter.next();
			retval.add(new SelectItem(next.getName(),next.getName()));
		}
		
		return retval;
	}
	
	public List getAvailableIntervals(){
		ArrayList retval = new ArrayList();
		WorkerType currentWorkerType = (WorkerType) ServiceTypeManager.getServiceTypeByName(selectedWorker);
		Iterator iter = currentWorkerType.getCompatibleIntervalTypeNames().iterator();
		while(iter.hasNext()){
			String name = (String) iter.next();
			retval.add(new SelectItem(name,name));
		}
		
		
		return retval;
	}
	
	public List getAvailableActions(){
		ArrayList retval = new ArrayList();
		WorkerType currentWorkerType = (WorkerType) ServiceTypeManager.getServiceTypeByName(selectedWorker);
		Iterator iter = currentWorkerType.getCompatibleActionTypeNames().iterator();
		while(iter.hasNext()){
			String name = (String) iter.next();
			retval.add(new SelectItem(name,name));
		}		
		return retval;
	}
	
	public void changeWorker(ValueChangeEvent e){
        System.out.println("changeWorker called to " + e.getNewValue());
		
	}
	
	public void changeInterval(ValueChangeEvent e){
        System.out.println("changeInterval called to " + e.getNewValue());
	}
	
	public void changeAction(ValueChangeEvent e){
        System.out.println("changeAction called to " + e.getNewValue());
	}
}

