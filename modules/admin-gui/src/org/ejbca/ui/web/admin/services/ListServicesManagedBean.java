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

import java.io.Serial;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.enterprise.context.SessionScoped;
import jakarta.faces.model.SelectItem;
import jakarta.inject.Named;
import org.apache.commons.lang3.StringUtils;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorkerConstants;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;
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

	@Serial
	private static final long serialVersionUID = 1L;

	private final List<String> availableServices = new ArrayList<>();
	private final Map<String, String> serviceNameToStatusMap = new HashMap<>();
	private final Map<String, String> serviceNameToTypeMap = new HashMap<>();

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

	/**
	 * Loads and prepares the list of available services along with their status and type configurations.
	 */
	public void loadData() {
		availableServices.clear();
		final Map<String, ServiceConfiguration> serviceNameToConfigurationMap = new HashMap<>();
		for (Integer id : getEjb().getServiceSession().getVisibleServiceIds()) {
			final ServiceConfiguration serviceConfiguration = getEjb().getServiceSession().getServiceConfiguration(id);
			if (!isAuthorizedToDbMaintenanceService() && DatabaseMaintenanceWorkerConstants.WORKER_CLASS.equals(serviceConfiguration.getWorkerClassPath())) {
				continue;
			}
			final String serviceName = getEjb().getServiceSession().getServiceName(id);
			serviceNameToConfigurationMap.put(serviceName, serviceConfiguration);
			String hidden = "";
			if (serviceConfiguration.isHidden()) {
				hidden = " <Hidden, Debug mode>";
			}
			availableServices.add(serviceName + hidden);
		}
		populateStatusMap(serviceNameToConfigurationMap);
		populateTypeMap(serviceNameToConfigurationMap);
	}

	/**
	 * Populates the {@link #serviceNameToStatusMap} with Active/Inactive statuses of loaded services.
	 *
	 * @param serviceConfigurationMap a map where the keys are service names and the values are
	 *                                {@link ServiceConfiguration} instances containing configuration details.
	 */
	private void populateStatusMap(final Map<String, ServiceConfiguration> serviceConfigurationMap) {
		final String activeLabel = EjbcaJSFHelper.getBean().getText().get("ACTIVE");
		final String inactiveLabel = EjbcaJSFHelper.getBean().getText().get("INACTIVE");
		serviceNameToStatusMap.clear();
		serviceConfigurationMap.forEach((serviceName, serviceConfiguration) ->
				serviceNameToStatusMap.put(serviceName, serviceConfiguration.isActive() ? activeLabel : inactiveLabel)
		);
	}

	/**
	 * Populates the {@link #serviceNameToTypeMap} with UI labels of loaded services.
	 *
	 * @param serviceConfigurationMap a map where the keys are service names and the values are
	 *                                {@link ServiceConfiguration} instances containing configuration details.
	 */
	private void populateTypeMap(final Map<String, ServiceConfiguration> serviceConfigurationMap) {
		final boolean isAuthorized = isAuthorizedToDbMaintenanceService();
		serviceNameToTypeMap.clear();
		serviceConfigurationMap.forEach((serviceName, serviceConfiguration) -> {
					final var serviceConfigurationView = new ServiceConfigurationView(serviceConfiguration, isAuthorized);
					final String type = getWorkerTypeLabel(serviceConfigurationView);
					serviceNameToTypeMap.put(serviceName, type);
				}
		);
	}

	/**
	 * Retrieves the type label for a given service.
	 *
	 * @param serviceConfigurationView the {@link ServiceConfigurationView} containing the worker type
	 * @return the label of the worker type as a {@link String}, or an empty string if no matching label is found
	 */
	private String getWorkerTypeLabel(final ServiceConfigurationView serviceConfigurationView) {
		final String typeId = generateTypeId(serviceConfigurationView.getWorkerType());
		return serviceConfigurationView.getAvailableWorkers().stream()
				.filter(worker -> worker.getValue().equals(typeId))
				.findFirst()
				.map(SelectItem::getLabel)
				.orElse("");
	}

	/**
	 * Generates a service worker type identifier that can be used to query {@link ServiceConfigurationView#getAvailableWorkers()} by value.
	 *
	 * @param workerType the type of the service worker
	 * @return the generated type identifier
	 */
	private String generateTypeId(final WorkerType workerType) {
		final String name = workerType.getName();
		final String classPath = workerType.getClassPath();
		if (workerType instanceof CustomWorkerType && StringUtils.isNotEmpty(classPath)) {
			return name + "-" + classPath;
		}
		return name;
	}

	public List<String> getAvailableServices() {
		return this.availableServices;
	}

	/**
	 * Retrieves a sorted list of available services.
	 * The services are sorted alphabetically by their display value, ignoring casing.
	 *
	 * @return a list of sorted {@link String} instances representing the available services
	 */
	public List<String> getSortedServicesList() {
		final List<String> serviceList = new ArrayList<>(getAvailableServices());
		serviceList.sort(Comparator.comparing(String::toString, String.CASE_INSENSITIVE_ORDER));
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
		if (getEjb().getServiceSession().getService(clonedServiceName) != null){
			addErrorMessage("SERVICENAMEALREADYEXISTS");
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

	/**
	 * Checks if the list of available services is empty.
	 *
	 * @return true if the list of available services is empty, false otherwise
	 */
	public boolean isServiceListEmpty() {
		return getAvailableServices().isEmpty();
	}

	/**
	 * Retrieves the service type based on its name.
	 *
	 * @param serviceName the name of the service whose type is to be retrieved
	 * @return the service type as a string, or an empty string if the service name does not exist
	 */
	public String getServiceType(final String serviceName) {
		if (serviceNameToTypeMap.containsKey(serviceName)) {
			return serviceNameToTypeMap.get(serviceName);
		}
		return "";
	}

	/**
	 * Retrieves the status of a specified service configuration.
	 *
	 * @param serviceName the name of the service whose status is to be retrieved
	 * @return the status of the service as a string if it exists, or an empty string if it does not
	 */
	public String getServiceStatus(final String serviceName) {
		if (serviceNameToStatusMap.containsKey(serviceName)) {
			return serviceNameToStatusMap.get(serviceName);
		}
		return "";
	}

	private EditServiceManagedBean getEditServiceBean(){
        return EditServiceManagedBean.getBean();
	}

	public EjbLocalHelper getEjb() {
		if (ejb == null) {
			ejb = new EjbLocalHelper();
		}
		return ejb;
	}
}
