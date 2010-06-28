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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;

/**
 * Class used to manage the listservices.jsp page
 * Contains and manages the available services
 * 
 * @author Philip Vendil 2006 sep 29
 *
 * @version $Id: ListServicesManagedBean.java 5585 2008-05-01 20:55:00Z anatom $
 */
public class ListServicesManagedBean extends BaseManagedBean {
	


	private String selectedServiceName;
	
	private String newServiceName = "";

	
	public ListServicesManagedBean(){
		

	}

	public String getSelectedServiceName() {
		return selectedServiceName;
	}

	public void setSelectedServiceName(String string) {
		selectedServiceName = string;
	}

	public List getAvailableServices() {
		List availableServices = new ArrayList();
	    Collection availableServicesIds = EjbcaJSFHelper.getBean().getServiceSession().getAuthorizedVisibleServiceIds(getAdmin());
	    Iterator iter = availableServicesIds.iterator();
	    while(iter.hasNext()){
	    	Integer id = (Integer) iter.next();
	    	ServiceConfiguration serviceConfig =  EjbcaJSFHelper.getBean().getServiceSession().getServiceConfiguration(getAdmin(), id.intValue());
	    	String serviceName = EjbcaJSFHelper.getBean().getServiceSession().getServiceName(getAdmin(), id.intValue());
	    	String hidden = "";
	    	if (serviceConfig.isHidden()) {
	    		hidden = "<Hidden, Debug mode>";
	    	}
	    	if(serviceConfig.isActive()){
	    		availableServices.add(new SortableSelectItem(serviceName, serviceName+ " (" + EjbcaJSFHelper.getBean().getText().get("ACTIVE") + ")" + hidden));
	    	}else{
	    		availableServices.add(new SortableSelectItem(serviceName, serviceName + " (" + EjbcaJSFHelper.getBean().getText().get("INACTIVE") + ")" + hidden));
	    	}
	    }
	    
	    Collections.sort(availableServices);
	 
		return availableServices;
	}


	
	public String editService(){
		String retval = "editservice";
		if(selectedServiceName != null){			
			try {
				getEditServiceBean().setServiceName(selectedServiceName);
				ServiceConfiguration serviceConf = EjbcaJSFHelper.getBean().getServiceSession().getService(getAdmin(), selectedServiceName);
				getEditServiceBean().setServiceConfiguration(serviceConf);
			} catch (IOException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("ERROREDITINGSERVICE") + " " + e.getMessage());						
			}				
		}else{
			addErrorMessage("YOUHAVETOSELECTASERVICE");
			retval = "listservices";
		}
		
		newServiceName = "";
		return retval;
	}
	
	public String deleteService(){
		if(selectedServiceName != null){
		  EjbcaJSFHelper.getBean().getServiceSession().removeService(getAdmin(), selectedServiceName);
		}else{
			addErrorMessage("YOUHAVETOSELECTASERVICE");
		}
		
		newServiceName = "";
		return "listservices";
	}
	
	public String renameService(){
		if(selectedServiceName == null){
			addErrorMessage("YOUHAVETOSELECTASERVICE");
		}else if (newServiceName.trim().equals("")) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		}else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		}else{			
			try {
				EjbcaJSFHelper.getBean().getServiceSession().renameService(getAdmin(), selectedServiceName, newServiceName);
			} catch (ServiceExistsException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("SERVICENAMEALREADYEXISTS"));
			}			
		}

		newServiceName = "";
		return "listservices";
	}
	


	public String addService(){
		if (newServiceName.trim().equals("")) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		}else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		}else{			
			try {
				ServiceConfiguration serviceConfig = new ServiceConfiguration();			
				EjbcaJSFHelper.getBean().getServiceSession().addService(getAdmin(), newServiceName, serviceConfig);
				getEditServiceBean().setServiceConfiguration(serviceConfig);
				getEditServiceBean().setServiceName(newServiceName);
			} catch (ServiceExistsException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("SERVICENAMEALREADYEXISTS"));
			} catch (IOException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("ERRORADDINGSERVICE") + e.getMessage());
			}
		}
		
		newServiceName = "";
		return "listservices";
	}
	
	public String cloneService(){
		if(selectedServiceName == null){
			addErrorMessage("YOUHAVETOSELECTASERVICE");
		}else if (newServiceName.trim().equals("")) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		}else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		}else{			
			try {
				EjbcaJSFHelper.getBean().getServiceSession().cloneService(getAdmin(), selectedServiceName, newServiceName);
			} catch (ServiceExistsException e) {
				addErrorMessage("SERVICENAMEALREADYEXISTS");				
			}			
		}
		
		newServiceName = "";
		return "listservices";
	}

	/**
	 * @return the newServiceName
	 */
	public String getNewServiceName() {
		return newServiceName;
	}

	/**
	 * @param newServiceName the newServiceName to set
	 */
	public void setNewServiceName(String newServiceName) {
		this.newServiceName = newServiceName;
	}

	/**
	 * returns true if the is a faulty service name.
	 * @param newServiceName
	 */
	private boolean errorInServiceName(String newServiceName) {
		return StringUtils.contains(newServiceName, ";");
	}

	private EditServiceManagedBean getEditServiceBean(){
		FacesContext context = FacesContext.getCurrentInstance();    
		Application app = context.getApplication();    
		ValueBinding binding = app.createValueBinding("#{editService}");    
		Object value = binding.getValue(context);    
		return (EditServiceManagedBean) value;
	}
	
}
