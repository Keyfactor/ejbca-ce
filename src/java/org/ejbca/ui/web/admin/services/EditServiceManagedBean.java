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
import java.util.List;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;
import javax.faces.event.ValueChangeEvent;
import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CertificateExpirationNotifierWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.MailActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class used to manage the GUI editing of a Service Configuration
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: EditServiceManagedBean.java,v 1.2 2006-10-14 05:01:48 herrvendil Exp $
 */
public class EditServiceManagedBean extends BaseManagedBean {
	
	private ServiceConfigurationView serviceConfigurationView;
	
	private String serviceName = "";
	

	
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
	
	public String update(){
		System.out.println("update pressed");
		return "editservice";
	}
	
	
	/**
	 * Help method used to edit data in the custom worker type.
	 */
	public CustomWorkerType getCustomWorkerType(){
		return (CustomWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomWorkerType.NAME);
	}
	
	/**
	 * Help method used to edit data in the custom action type.
	 */
	public CustomActionType getCustomActionType(){
		return (CustomActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomActionType.NAME);
	}	
	
	/**
	 * Help method used to edit data in the custom interval type.
	 */
	public CustomIntervalType getCustomIntervalType(){
		return (CustomIntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CustomIntervalType.NAME);
	}
	
	/**
	 * Help method used to edit data in the mail action type.
	 */
	public MailActionType getMailActionType(){
		return (MailActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(MailActionType.NAME);
	}	
	
	/**
	 * Help method used to edit data in the certificate expriation worker type.
	 */
	public CertificateExpirationNotifierWorkerType getCertificateExpriationType(){
		return (CertificateExpirationNotifierWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CertificateExpirationNotifierWorkerType.NAME);
	}
	
	/**
	 * Help method used to edit data in the custom interval type.
	 */
	public PeriodicalIntervalType getPeriodicalIntervalType(){
		return (PeriodicalIntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(PeriodicalIntervalType.NAME);
	}

	public void changeWorker(ValueChangeEvent e){
		
		String newName = (String) e.getNewValue();
		WorkerType newWorkerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
		serviceConfigurationView.setWorkerType(newWorkerType);
		serviceConfigurationView.setSelectedWorker(newName);
		
        System.out.println("changeWorker called to " + e.getNewValue());
		
	}
	
	public void changeInterval(ValueChangeEvent e){
		String newName = (String) e.getNewValue();
		
		WorkerType workerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(serviceConfigurationView.getSelectedWorker());
		if(workerType.getCompatibleIntervalTypeNames().contains(newName)){
			IntervalType newIntervalType = (IntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
			serviceConfigurationView.setIntervalType(newIntervalType);
			serviceConfigurationView.setSelectedInterval(newName);
			System.out.println("changeInterval called to " + e.getNewValue());
		}else{
			System.out.println("changeInterval called to not changed");
		}
	}
	
	public void changeAction(ValueChangeEvent e){
		
		String newName = (String) e.getNewValue();
		
		WorkerType workerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(serviceConfigurationView.getSelectedWorker());
		if(workerType.getCompatibleActionTypeNames().contains(newName)){
		  ActionType newActionType = (ActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
		  serviceConfigurationView.setActionType(newActionType);
		  serviceConfigurationView.setSelectedAction(newName);
		  System.out.println("changeAction called to " + e.getNewValue());
		}else{
			 System.out.println("changeAction called to not changed");
		}
	}
	
	public List getAvailableCAs(){
		//TODO
		ArrayList retval = new ArrayList();
		retval.add(new SelectItem("AdminCA1","AdminCA1"));
		retval.add(new SelectItem("AdminCA2","AdminCA2"));
		retval.add(new SelectItem("AdminCA3","AdminCA3"));
		
		return retval;
		
	}

}

