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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.IAction;
import org.ejbca.core.model.services.IInterval;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.services.servicetypes.ActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.IntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.NoActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Class responsible for converting the data between the GUI and a
 * SystemConfiguration VO
 *
 * @version $Id$
 */
public class ServiceConfigurationView implements Serializable{

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ServiceConfigurationView.class);
	
	private WorkerType workerType;
	private ActionType actionType;
	private IntervalType intervalType;
	
    private String selectedInterval;
    private String selectedAction;
    
    private ServiceTypeManager typeManager;
	
	private boolean active = false;
	private boolean hidden = false;
	private String description = "";
	private String[] pinToNodes = new String[0];
	
	private ServiceConfiguration serviceConfiguration;
	
	public ServiceConfigurationView(ServiceConfiguration serviceConfiguration) {
		
		typeManager = new ServiceTypeManager();
	
		this.serviceConfiguration = serviceConfiguration;
		WorkerType workerType = (WorkerType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getWorkerClassPath());
		if (workerType == null) {
		    workerType = (WorkerType) typeManager.getServiceTypeByName(CustomWorkerType.NAME);
		    ((CustomWorkerType) workerType).setClassPath(serviceConfiguration.getWorkerClassPath());
		}			
	    setWorkerType(workerType);
		
		IntervalType intervalType = (IntervalType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getIntervalClassPath());
		if (intervalType == null) {
		    if (workerType.getCompatibleIntervalTypeNames().contains(PeriodicalIntervalType.NAME)) {
	            // It seems most likely that the admin wants to configure a periodic interval even if custom interval are available
	            intervalType = (IntervalType) typeManager.getServiceTypeByName(PeriodicalIntervalType.NAME);
		    } else {
	            intervalType = (IntervalType) typeManager.getServiceTypeByName(CustomIntervalType.NAME);
	            ((CustomIntervalType) intervalType).setClassPath(serviceConfiguration.getIntervalClassPath());
		    }
		}						
		setIntervalType(intervalType);
		selectedInterval = intervalType.getName();
		
		ActionType actionType = (ActionType) typeManager.getServiceTypeByClassPath(serviceConfiguration.getActionClassPath());
		if (actionType == null) {
            if (workerType.getCompatibleActionTypeNames().contains(NoActionType.NAME)) {
                // It seems most likely that the admin wants to configure a "no action" action even if custom actions are available
                actionType = (ActionType) typeManager.getServiceTypeByName(NoActionType.NAME);
            } else {
                actionType = (ActionType) typeManager.getServiceTypeByName(CustomActionType.NAME);
                ((CustomActionType) actionType).setClassPath(serviceConfiguration.getActionClassPath());
            }
		}						
	    setActionType(actionType);
	    selectedAction = actionType.getName();
		
		setDescription(serviceConfiguration.getDescription());
		setActive(serviceConfiguration.isActive());
		setHidden(serviceConfiguration.isHidden());
		setPinToNodes(serviceConfiguration.getPinToNodes());
	}
	
	/**
	 * Method that populates a service configuration from a
	 * GUI data.
	 */
	public ServiceConfiguration getServiceConfiguration(ArrayList<String> errorMessages) throws IOException{
		ServiceConfiguration retval = new ServiceConfiguration();
		retval.setActive(isActive());
		retval.setHidden(isHidden());
		retval.setDescription(getDescription());
		retval.setActionClassPath(getActionType().getClassPath());
		retval.setActionProperties(getActionType().getProperties(errorMessages)); 
		retval.setIntervalClassPath(getIntervalType().getClassPath());
		retval.setIntervalProperties(getIntervalType().getProperties(errorMessages));
		retval.setWorkerClassPath(getWorkerType().getClassPath());
		retval.setWorkerProperties(getWorkerType().getProperties(errorMessages));
		retval.setPinToNodes(getPinToNodes());
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
		try {
			actionType.setProperties(serviceConfiguration.getActionProperties());
		} catch (IOException e) {
		  log.error(e);
		}
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

	public boolean isHidden() {
		return hidden;
	}

	/**
	 * @param active the active to set
	 */
	public void setHidden(boolean hidden) {
		this.hidden = hidden;
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
		try {
			intervalType.setProperties(serviceConfiguration.getIntervalProperties());
		} catch (IOException e) {
		  log.error(e);
		}
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
		try{
		  workerType.setProperties(serviceConfiguration.getWorkerProperties());
		  this.workerType = workerType;
		  
		
		  if(selectedInterval != null && !workerType.getCompatibleIntervalTypeNames().contains(selectedInterval)){				
			setSelectedInterval((String) workerType.getCompatibleIntervalTypeNames().iterator().next());
			setIntervalType((IntervalType) typeManager.getServiceTypeByName(getSelectedInterval()));
		  }
		  
		
		  if(selectedAction != null && !workerType.getCompatibleActionTypeNames().contains(selectedAction)){
			setSelectedAction((String) workerType.getCompatibleActionTypeNames().iterator().next());
			setActionType((ActionType) typeManager.getServiceTypeByName(getSelectedAction()));
		  }
		  
		}catch(IOException e){
			log.error(e);
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
	    final WorkerType workerType = getWorkerType();
	    if (workerType instanceof CustomWorkerType) {
	        final CustomWorkerType customWorkerType = (CustomWorkerType) workerType;
	        if (customWorkerType.getClassPath()!=null && customWorkerType.getClassPath().length()>0) {
	            return workerType.getName() + "-" + customWorkerType.getClassPath();
	        }
	    }
		return workerType.getName();
	}

	/**
	 * @param selectedWorker the selectedWorker to set
	 */
	public void setSelectedWorker(final String selectedWorker) {
	    final int separatorPos = selectedWorker.indexOf('-');
	    if (separatorPos==-1) {
	        final WorkerType workerType = (WorkerType) getServiceTypeManager().getServiceTypeByName(selectedWorker);
	        if (workerType instanceof CustomWorkerType) {
	            ((CustomWorkerType) workerType).setClassPath("");
	        }
	        setWorkerType(workerType);
	    } else {
	        final String customClassPath = selectedWorker.split("-")[1];
	        final WorkerType workerType = (WorkerType) typeManager.getServiceTypeByName(CustomWorkerType.NAME);
            ((CustomWorkerType) workerType).setClassPath(customClassPath);
	        setWorkerType(workerType);
	    }
	}	
	
	public List<SelectItem> getAvailableWorkers(){
		final ArrayList<SelectItem> retval = new ArrayList<SelectItem>();
		final Collection<ServiceType> available = typeManager.getAvailableWorkerTypes();
		for (final ServiceType next : available) {
			String label = next.getName();
			if (next.isTranslatable()) {
				label = EjbcaJSFHelper.getBean().getText().get(next.getName());
			}
            retval.add(new SelectItem(next.getName(),label));
			if (next instanceof CustomWorkerType) {
		        List<String> customClasses = CustomLoader.getCustomClasses(IWorker.class);
		        for (final String customClass : customClasses) {
		            final String customClassSimpleName = customClass.substring(customClass.lastIndexOf('.')+1);
		            final String labelKey = customClassSimpleName.toUpperCase()+"_TITLE";
		            label = EjbcaJSFHelper.getBean().getText().get(labelKey);
		            if (label.equals(labelKey)) {
		                label = customClassSimpleName + " ("+EjbcaJSFHelper.getBean().getText().get(next.getName())+")";
		            }
		            retval.add(new SelectItem(next.getName()+"-"+customClass, label));
		        }
			}
		}
		// Sort by label
		Collections.sort(retval, new Comparator<SelectItem>() {
            @Override
            public int compare(SelectItem arg0, SelectItem arg1) {
                return arg0.getLabel().compareTo(arg1.getLabel());
            }
		});
		return retval;
	}
	
	public List<SelectItem> getAvailableIntervals(){
		final ArrayList<SelectItem> retval = new ArrayList<SelectItem>();
		final WorkerType currentWorkerType = getWorkerType();
		for (final String name : currentWorkerType.getCompatibleIntervalTypeNames()) {
			final ServiceType next = typeManager.getServiceTypeByName(name);
			String label = name;
			if(next.isTranslatable()){
				label = (String) EjbcaJSFHelper.getBean().getText().get(name);
			}
			retval.add(new SelectItem(name,label));
		}
		return retval;
	}
	
	public List<SelectItem> getAvailableActions(){
		final ArrayList<SelectItem> retval = new ArrayList<SelectItem>();
		final WorkerType currentWorkerType = getWorkerType();
		for (final String name : currentWorkerType.getCompatibleActionTypeNames()) {
			final ServiceType next = typeManager.getServiceTypeByName(name);
			String label = name;
			if (next.isTranslatable()) {
				label = (String) EjbcaJSFHelper.getBean().getText().get(name);
			}
			retval.add(new SelectItem(name,label));
		}		
		return retval;
	}
	
	private List<SelectItem> stringsToItems(List<String> stringList) {
	   List<SelectItem> itemList = new ArrayList<SelectItem>(stringList.size());
	   for (String s : stringList) {
	       itemList.add(new SelectItem(s, s));
	   }
	   return itemList;
	}
	
	public List<SelectItem> getAvailableCustomWorkerItems() {
	    final List<String> customClasses = CustomLoader.getCustomClasses(IWorker.class);
	    final List<String> customClassesWithoutUiSupport = new ArrayList<String>();
	    for (final String classPath : customClasses) {
	    	// Exclude all the workers that have custom UI support and will be shown as any other worker
	        if (!CustomWorkerType.isCustomUiRenderingSupported(classPath)) {
	            customClassesWithoutUiSupport.add(classPath);
	        }
	    }
	    return stringsToItems(customClassesWithoutUiSupport);
	}
	
	public List<SelectItem> getAvailableCustomIntervalItems() {
       return stringsToItems(CustomLoader.getCustomClasses(IInterval.class));
    }
    
    public List<SelectItem> getAvailableCustomActionItems() {
       return stringsToItems(CustomLoader.getCustomClasses(IAction.class));
    }
	
	/** returns this sessions service type manager */
	public ServiceTypeManager getServiceTypeManager(){
		return typeManager;
	}

	public String[] getPinToNodes() {
		return pinToNodes;
	}

	public void setPinToNodes(String[] pinToNodes) {
		if (log.isDebugEnabled()) {
			log.debug("view setPinToNodes: " + Arrays.toString(pinToNodes));
		}
		this.pinToNodes = pinToNodes;
	}
	
	public List<SelectItem> getNodesInCluster() {
		final List<SelectItem> ret = new LinkedList<SelectItem>();
		final Set<String> nodes = EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getNodesInCluster();  
		for (String node : nodes) {
			ret.add(new SelectItem(node));
		}
		// Also add unknown nodes, that is nodes that has been removed but this service still is pinned to
		for (String node : getPinToNodes()) {
			if (!nodes.contains(node)) {
				ret.add(new SelectItem(node, node + " " + EjbcaJSFHelper.getBean().getText().get("PINTONODESUNKNOWNNODE")));
			}
		}
		return ret; 
	}

}
