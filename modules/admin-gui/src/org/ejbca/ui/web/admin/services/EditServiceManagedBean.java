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
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.workers.CRLUpdateWorker;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.PublishQueueProcessWorker;
import org.ejbca.core.model.services.workers.RenewCAWorker;
import org.ejbca.core.model.services.workers.UserPasswordExpireWorker;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.BaseEmailNotifyingWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.BaseWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CRLUpdateWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CertificateExpirationNotifierWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.MailActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.PublishQueueWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.RenewCAWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.UserPasswordExpireWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class used to manage the GUI editing of a Service Configuration
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: EditServiceManagedBean.java 8461 2009-12-21 15:22:17Z jeklund $
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
			  EjbcaJSFHelper.getBean().getServiceSession().changeService(getAdmin(), serviceName, serviceConfigurationView.getServiceConfiguration(errorMessages), false);
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
	
	public BaseWorkerType getBaseWorkerType() {
		String name = null;
		try {
			ServiceConfiguration conf = serviceConfigurationView.getServiceConfiguration(new ArrayList());		
			String cp = conf.getWorkerClassPath();
			name = getTypeNameFromClassPath(cp);			
		} catch (IOException e) {
			log.error(e);
		}
		if (log.isDebugEnabled()) {
			log.debug("Get baseWorkerType by name: "+name);
		}
		BaseWorkerType ret = (BaseWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
		return ret; 		
	}
	
	/**
	 * Help method used to edit data in the notifying worker type.
	 */
	public BaseEmailNotifyingWorkerType getNotifyingType(){
		log.trace(">getNotifyingType");
		BaseEmailNotifyingWorkerType ret = null;
		BaseWorkerType type = getBaseWorkerType();	
		if (type instanceof BaseEmailNotifyingWorkerType) {
			ret = (BaseEmailNotifyingWorkerType)type;
		} else {
			// Use default type in order to avoid model update errors when switching to a worker with a different type
			// i.e. switching for example from CertificateExpirationWorker to CRLUpdateWorker
			// We can't return null either so...
			ret =(BaseEmailNotifyingWorkerType)serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(CertificateExpirationNotifierWorkerType.NAME);
		}
		log.trace("<getNotifyingType");
		return ret;
	}

	private String getTypeNameFromClassPath(String cp) {
		log.debug("ClassPath: "+cp);
		String ret = null;
		if ( (cp != null) && cp.equals(CertificateExpirationNotifierWorker.class.getName()) ) {
			ret = CertificateExpirationNotifierWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(UserPasswordExpireWorker.class.getName()) ) {
			ret = UserPasswordExpireWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(RenewCAWorker.class.getName()) ) {
			ret = RenewCAWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(PublishQueueProcessWorker.class.getName()) ) {
			ret = PublishQueueWorkerType.NAME;
		}			
		if ( (cp != null) && cp.equals(CRLUpdateWorker.class.getName()) ) {
			ret = CRLUpdateWorkerType.NAME;
		}
		return ret;
	}

	/**
	 * Help method used to edit data in the RenewCAWorkerType.
	 */
	public RenewCAWorkerType getRenewType(){
		String name = RenewCAWorkerType.NAME;
		return (RenewCAWorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(name);
	}

	/** Help method to edit data in the publish queue worker type
	 */
	public PublishQueueWorkerType getPublishWorkerType() {
		return (PublishQueueWorkerType)serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(PublishQueueWorkerType.NAME);
	}
	
	/**
	 * Help method used to edit data in the custom interval type.
	 */
	public PeriodicalIntervalType getPeriodicalIntervalType(){
		return (PeriodicalIntervalType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(PeriodicalIntervalType.NAME);
	}

	public void changeWorker(ValueChangeEvent e){
		log.trace(">changeWorker");		
		String newName = (String) e.getNewValue();
		WorkerType newWorkerType = (WorkerType) serviceConfigurationView.getServiceTypeManager().getServiceTypeByName(newName);
		serviceConfigurationView.setWorkerType(newWorkerType);
		serviceConfigurationView.setSelectedWorker(newName);
		log.trace("<changeWorker");		
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
	
	/** Returns the list of available CAs, only including the actually present CAs.
	 * 
	 * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
	 */
	public List getAvailableCAs() {
		return getAvailableCAs(false);
	}
	/** Returns the list of available CAs, also including the special option 'Any CA'.
	 * 
	 * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
	 */
	public List getAvailableCAsWithAnyOption() {
		return getAvailableCAs(true);
	}

	/** Returns the list of available CAs
	 * 
	 * @param includeAllCAs if the returned list should include the constant ALLCAs or only the actually available CAs.
	 * @return List<javax.faces.model.SelectItem>(String, String) of CA id's (as String) and CA names
	 */
	private List getAvailableCAs(boolean includeAllCAs) {
		List availableCANames = new ArrayList();
		Collection cAIds = EjbcaJSFHelper.getBean().getCAAdminSession().getAvailableCAs(getAdmin());
		Iterator iter = cAIds.iterator();
		while(iter.hasNext()){
			int next = ((Integer) iter.next()).intValue();
			availableCANames.add(new SelectItem(Integer.valueOf(next).toString(), EjbcaJSFHelper.getBean().getCAAdminSession().getCAInfo(getAdmin(), next).getName()));
		}
		if (includeAllCAs) {
			String caname = (String)EjbcaJSFHelper.getBean().getText().get("ANYCA");
			availableCANames.add(new SelectItem(Integer.valueOf(SecConst.ALLCAS).toString(), caname));
		}
		return availableCANames;		
	}

	public List getAvailablePublishers(){
		List availablePublisherNames = new ArrayList();
		Collection publisherIds = EjbcaJSFHelper.getBean().getCAAdminSession().getAuthorizedPublisherIds(getAdmin());
		Iterator iter = publisherIds.iterator();
		while(iter.hasNext()){
			int next = ((Integer) iter.next()).intValue();
			// Display it in the list as "PublisherName (publisherId)" with publisherId as the value sent
			availablePublisherNames.add(new SelectItem(Integer.valueOf(next).toString(), EjbcaJSFHelper.getBean().getPublisherSession().getPublisherName(getAdmin(), next)+" ("+next+")"));
		}
		return availablePublisherNames;		
	}


}

