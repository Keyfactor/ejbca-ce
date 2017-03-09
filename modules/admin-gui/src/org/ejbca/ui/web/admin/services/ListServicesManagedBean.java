/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.faces.application.Application;
import javax.faces.context.FacesContext;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;

/**
 * Class used to manage the listservices.jsp page
 * Contains and manages the available services
 * 
 *
 * @version $Id$
 */
public class ListServicesManagedBean extends BaseManagedBean {

	private static final long serialVersionUID = 1L;
	private final EjbLocalHelper ejb = new EjbLocalHelper();
	private String selectedServiceName;
	private String newServiceName = "";

	public ListServicesManagedBean() { }

	public String getSelectedServiceName() {
		return selectedServiceName;
	}

	public void setSelectedServiceName(String string) {
		selectedServiceName = string;
	}

    public List<SortableSelectItem> getAvailableServices() {
        List<SortableSelectItem> availableServices = new ArrayList<SortableSelectItem>();
        Collection<Integer> availableServicesIds = ejb.getServiceSession().getVisibleServiceIds();
        for (Integer id : availableServicesIds) {
            ServiceConfiguration serviceConfig = ejb.getServiceSession().getServiceConfiguration(id.intValue());
            String serviceName = ejb.getServiceSession().getServiceName(id.intValue());
            String hidden = "";
            if (serviceConfig.isHidden()) {
                hidden = "<Hidden, Debug mode>";
            }
            if (serviceConfig.isActive()) {
                availableServices.add(new SortableSelectItem(serviceName, serviceName + " (" + EjbcaJSFHelper.getBean().getText().get("ACTIVE") + ")"
                        + hidden));
            } else {
                availableServices.add(new SortableSelectItem(serviceName, serviceName + " (" + EjbcaJSFHelper.getBean().getText().get("INACTIVE")
                        + ")" + hidden));
            }
        }
        Collections.sort(availableServices);
        return availableServices;
    }

	public String editService(){
		String retval = "editservice";
        if (StringUtils.isNotEmpty(selectedServiceName)) {
            getEditServiceBean().setServiceName(selectedServiceName);
            ServiceConfiguration serviceConf = ejb.getServiceSession().getService(selectedServiceName);
            getEditServiceBean().setServiceConfiguration(serviceConf);
        } else {
			addErrorMessage("YOUHAVETOSELECTASERVICE");
			retval = "listservices";
		}
		newServiceName = "";
		return retval;
	}
	
	public String deleteService(){
        if (StringUtils.isNotEmpty(selectedServiceName)) {
			ejb.getServiceSession().removeService(getAdmin(), selectedServiceName);
		}else{
			addErrorMessage("YOUHAVETOSELECTASERVICE");
		}
		newServiceName = "";
		return "listservices";
	}
	
	public String renameService(){
        if (StringUtils.isEmpty(selectedServiceName)) {
			addErrorMessage("YOUHAVETOSELECTASERVICE");
        } else if (StringUtils.isEmpty(StringUtils.trim(newServiceName))) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		} else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		} else {			
			try {
				ejb.getServiceSession().renameService(getAdmin(), selectedServiceName, newServiceName);
			} catch (ServiceExistsException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("SERVICENAMEALREADYEXISTS"));
			}			
		}
		newServiceName = "";
		return "listservices";
	}

	public String addService(){
		if (StringUtils.isEmpty(StringUtils.trim(newServiceName))) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		} else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		} else {			
			try {
				ServiceConfiguration serviceConfig = new ServiceConfiguration();			
				ejb.getServiceSession().addService(getAdmin(), newServiceName, serviceConfig);
				getEditServiceBean().setServiceConfiguration(serviceConfig);
				getEditServiceBean().setServiceName(newServiceName);
			} catch (ServiceExistsException e) {
				addNonTranslatedErrorMessage((String) EjbcaJSFHelper.getBean().getText().get("SERVICENAMEALREADYEXISTS"));
			} 
		}
		newServiceName = "";
		return "listservices";
	}
	
	public String cloneService(){
		if (StringUtils.isEmpty(selectedServiceName)) {
			addErrorMessage("YOUHAVETOSELECTASERVICE");
        } else if (StringUtils.isEmpty(StringUtils.trim(newServiceName))) {
			addErrorMessage("YOUHAVETOENTERASERVICE");
		} else if (errorInServiceName(newServiceName)) {
			addErrorMessage("THECHARACTERSARENTALLOWED");
		} else {			
			try {
				ejb.getServiceSession().cloneService(getAdmin(), selectedServiceName, newServiceName);
			} catch (ServiceExistsException e) {
				addErrorMessage("SERVICENAMEALREADYEXISTS");				
			}			
		}
		newServiceName = "";
		return "listservices";
	}

	/** @return the newServiceName  */
	public String getNewServiceName() {
		return newServiceName;
	}

	/** @param newServiceName the newServiceName to set */
	public void setNewServiceName(String newServiceName) {
		this.newServiceName = newServiceName;
	}

	/** 
	 * @return true if admin has access to /services/edit
	 */
	public boolean getHasEditRights() {
	    return ejb.getAuthorizationSession().isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_EDIT);
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
		EditServiceManagedBean value =  (EditServiceManagedBean) app.evaluateExpressionGet(context, "#{editService}", EditServiceManagedBean.class);
		return value;
	}
}
