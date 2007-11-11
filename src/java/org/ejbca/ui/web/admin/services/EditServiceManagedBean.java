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

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.BaseNotifyingWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CertificateExpirationNotifierWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.MailActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.UserPasswordExpireWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class used to manage the GUI editing of a Service Configuration
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: EditServiceManagedBean.java,v 1.6 2007-11-11 07:56:25 anatom Exp $
 */
public class EditServiceManagedBean extends BaseManagedBean {
	private static final Logger log = Logger.getLogger(EditServiceManagedBean.class);
	
	private ServiceConfigurationView serviceConfigurationView;
	
	private String serviceName = "";
	

	
	public EditServiceManagedBean(){
        try {
			setServiceConfiguration(new ServiceConfiguration());
		} catch (IOException e) {
			log.error(e);
		}
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
		String retval = "listservices";
		ArrayList errorMessages = new ArrayList();
		try {
			serviceConfigurationView.getServiceConfiguration(errorMessages);
			if(errorMessages.size() == 0){
			  EjbcaJSFHelper.getBean().getServiceSession().changeService(getAdmin(), serviceName, serviceConfigurationView.getServiceConfiguration(errorMessages));
			  EjbcaJSFHelper.getBean().getServiceSession().activateServiceTimer(getAdmin(), serviceName);
			}else{
				Iterator iter = errorMessages.iterator();
				while(iter.hasNext()){
					addErrorMessage((String) iter.next());
				}
				
				retval = null;				
			}
		} catch (IOException e) {
			addErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("ERROREDITINGSERVICE") + " " + e.getMessage());
		}
		
		return retval;
	}
	
	public String cancel(){		
		return "listservices";
	}
	
	public String update(){
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
	 * Help method used to edit data in the notifying worker type.
	 */
	public BaseNotifyingWorkerType getNotifyingType(){
		String name = CertificateExpirationNotifierWorkerType.NAME;
		try {
			ServiceConfiguration conf = serviceConfigurationView.getServiceConfiguration(new ArrayList());		
			String cp = conf.getWorkerClassPath();
			log.debug("ClassPath: "+cp);
			if ( (cp != null) && cp.equals(UserPasswordExpireWorker.class.getName()) ) {
				name = UserPasswordExpireWorkerType.NAME;
			}			
		} catch (IOException e) {
			log.error(e);
		}
		return (BaseNotifyingWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
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
		
		
	}
	
	public void changeInterval(ValueChangeEvent e){
		String newName = (String) e.getNewValue();
		
		WorkerType workerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(serviceConfigurationView.getSelectedWorker());
		if(workerType.getCompatibleIntervalTypeNames().contains(newName)){
			IntervalType newIntervalType = (IntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
			serviceConfigurationView.setIntervalType(newIntervalType);
			serviceConfigurationView.setSelectedInterval(newName);			
		}
	}
	
	public void changeAction(ValueChangeEvent e){
		
		String newName = (String) e.getNewValue();
		
		WorkerType workerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(serviceConfigurationView.getSelectedWorker());
		if(workerType.getCompatibleActionTypeNames().contains(newName)){
		  ActionType newActionType = (ActionType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
		  serviceConfigurationView.setActionType(newActionType);
		  serviceConfigurationView.setSelectedAction(newName);		  
		}
	}
	
	public List getAvailableCAs(){
		List availableCANames = new ArrayList();
		Collection cAIds = EjbcaJSFHelper.getBean().getCAAdminSession().getAvailableCAs(getAdmin());
		Iterator iter = cAIds.iterator();
		while(iter.hasNext()){
			int next = ((Integer) iter.next()).intValue();
			availableCANames.add(new SelectItem(new Integer(EjbcaJSFHelper.getBean().getCAAdminSession().getCAInfo(getAdmin(), next).getCAId()).toString(),EjbcaJSFHelper.getBean().getCAAdminSession().getCAInfo(getAdmin(), next).getName()));
		}
		
		return availableCANames;
		
	}

}

