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
import java.util.Comparator;
import java.util.List;

import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.application.Application;
import jakarta.faces.context.FacesContext;
import jakarta.faces.model.SelectItem;
import jakarta.inject.Named;
import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorkerConstants;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.SortableSelectItem;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class used to manage the listservices.xhtml page
 * Contains and manages the available services
 * 
 *
 */
@Named("listServicesManagedBean")
@SessionScoped
public class ListServicesManagedBean extends BaseManagedBean {

	private static final long serialVersionUID = 1L;
	private String selectedServiceName;
	private String clonedServiceName = StringUtils.EMPTY;

	// this shouldn't be serialized - only access via getter
	private transient EjbLocalHelper ejb = new EjbLocalHelper();

	public ListServicesManagedBean() {
	    super(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.SERVICES_VIEW);
	}
	
	public String getSelectedServiceName() {
		return selectedServiceName;
	}

	public void setSelectedServiceName(String string) {
		selectedServiceName = string;
	}

	public String getClonedServiceName() {
		return clonedServiceName;
	}

	public void setClonedServiceName(final String clonedServiceName) {
		this.clonedServiceName = clonedServiceName;
	}

    public List<SortableSelectItem> getAvailableServices() {
        List<SortableSelectItem> availableServices = new ArrayList<>();
        Collection<Integer> availableServicesIds = getEjb().getServiceSession().getVisibleServiceIds();
		boolean isAuthorizedToDbMaintenanceService = isAuthorizedToDbMaintenanceService();
		for (Integer id : availableServicesIds) {
            ServiceConfiguration serviceConfig = getEjb().getServiceSession().getServiceConfiguration(id);
            String serviceName = getEjb().getServiceSession().getServiceName(id);
			if (!isAuthorizedToDbMaintenanceService && DatabaseMaintenanceWorkerConstants.WORKER_CLASS.equals(serviceConfig.getWorkerClassPath())) {
				continue;
			}
            String hidden = "";
            if (serviceConfig.isHidden()) {
                hidden = "<Hidden, Debug mode>";
            }
            if (serviceConfig.isActive()) {
                availableServices.add(new SortableSelectItem(serviceName, EjbcaJSFHelper.getBean().getText().get("ACTIVE") + hidden));
            } else {
                availableServices.add(new SortableSelectItem(serviceName, EjbcaJSFHelper.getBean().getText().get("INACTIVE") + hidden));
            }
        }
		return availableServices;
    }

	/**
	 * Retrieves a sorted list of available services.
	 * The services are sorted alphabetically by their display value, ignoring casing.
	 *
	 * @return a list of sorted {@link SortableSelectItem} instances representing the available services
	 */
	public List<SortableSelectItem> getSortedServicesList() {
		final List<SortableSelectItem> serviceList = new ArrayList<>(getAvailableServices());
		serviceList.sort(Comparator.comparing(SelectItem::getValue, Comparator.comparing(Object::toString, String.CASE_INSENSITIVE_ORDER)));
		return serviceList;
	}

	/**
	 * Prepares the service details for view-only mode and navigates to the edit service page.
	 *
	 * @param serviceName the name of the service to view
	 * @return "edit" - the view ID of the edit service page
	 */
	public String viewService(final String serviceName) {
		getEditServiceBean().setViewOnly(true);
		getEditServiceBean().setOriginalServiceName(serviceName);
		final ServiceConfiguration serviceConfiguration = ejb.getServiceSession().getService(serviceName);
		getEditServiceBean().setServiceConfiguration(serviceConfiguration);
		return "edit";
	}

	/**
	 * Prepares the specified service for editing and navigates to the edit service page.
	 *
	 * @param serviceName the name of the service to be edited
	 * @return "edit" - the view ID of the edit service page
	 */
	public String editService(final String serviceName) {
		getEditServiceBean().setViewOnly(false);
		getEditServiceBean().setOriginalServiceName(serviceName);
		final ServiceConfiguration serviceConfiguration = ejb.getServiceSession().getService(serviceName);
		getEditServiceBean().setServiceConfiguration(serviceConfiguration);
		return "edit";
	}

	/**
	 * Navigates to the deletion confirmation page.
	 *
	 * @param serviceName the name of the service to be deleted
	 * @return "delete" - the view ID for the deletion confirmation page
	 */
	public String confirmServiceDeletion(final String serviceName) {
		selectedServiceName = serviceName;
		return "delete";
	}

	/**
	 * Deletes the specified service from the system.
	 *
	 * @param serviceName the name of the service to be deleted
	 * @return "done" - the view ID used to navigate back to the service list page
	 */
	public String deleteService(final String serviceName){
		getEjb().getServiceSession().removeService(getAdmin(), serviceName);
		return "done";
	}

	/**
	 * Prepares a new service for creation and navigates to the edit service page.
	 *
	 * @return "edit" - the view ID of the edit service page
	 */
	public String addService(){
		getEditServiceBean().setViewOnly(false);
		getEditServiceBean().setOriginalServiceName("");
		getEditServiceBean().setServiceConfiguration(new ServiceConfiguration());
		return "edit";
	}

	/**
	 * Navigates to the page for cloning a service.
	 *
	 * @param serviceName the name of the template service
	 * @return "clone" - the view ID of the clone page
	 */
	public String cloneService(final String serviceName) {
		selectedServiceName = serviceName;
		clonedServiceName = "";
		return "clone";
	}

	/**
	 * Clones an existing service into a new one with the specified name.
	 *
	 * @return "done" - the view ID used to navigate back to the service list page
	 */
	public String cloneService() {
		if (getEditServiceBean().isServiceNameInvalid(clonedServiceName)) {
			return "";
		}
		try {
			getEjb().getServiceSession().cloneService(getAdmin(), selectedServiceName, clonedServiceName);
		} catch (ServiceExistsException e) {
			addErrorMessage("SERVICENAMEALREADYEXISTS");
		}
		return "done";
	}

	/** 
	 * @return true if admin has access to /services/edit
	 */
	public boolean getHasEditRights() {
	    return getEjb().getAuthorizationSession().isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_EDIT);
	}

	/**
	 * @return true if admin has access to /services/dbMaintenance
	 */
	private boolean isAuthorizedToDbMaintenanceService() {
		return getEjb().getAuthorizationSession().isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_DB_MAINTENANCE);
	}

	private EditServiceManagedBean getEditServiceBean(){
		FacesContext context = FacesContext.getCurrentInstance();    
		Application app = context.getApplication();   
		EditServiceManagedBean value =  app.evaluateExpressionGet(context, "#{editService}", EditServiceManagedBean.class);
		return value;
	}

	/**
	 * Checks if the list of available services is empty.
	 *
	 * @return true if the list of available services is empty, false otherwise
	 */
	public boolean isServiceListEmpty() {
		return getAvailableServices().isEmpty();
	}

	public EjbLocalHelper getEjb() {
		if (ejb == null) {
			ejb = new EjbLocalHelper();
		}
		return ejb;
	}
}
