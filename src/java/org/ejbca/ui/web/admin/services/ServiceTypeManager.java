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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;

/**
 * Central class managing available services types. New workers, actions, intervals
 * should be registered in the class in order to proved GUI to it.
 * 
 * To this there is also a need for a JSFSubView page with it's managed beans.
 *
 * @author Philip Vendil 2006 sep 29
 *
 * @version $Id: ServiceTypeManager.java,v 1.1 2006-10-01 17:46:48 herrvendil Exp $
 */
public class ServiceTypeManager {
	
	private static HashMap availableTypesByName = new HashMap();
	private static HashMap availableTypesByClassPath = new HashMap();
	private static ArrayList workerTypes = new ArrayList();
	
	static{
		ServiceTypeManager.registerServiceType(new CustomIntervalType());
		ServiceTypeManager.registerServiceType(new CustomActionType());		
		ServiceTypeManager.registerServiceType(new CustomWorkerType());
	}
	


	protected ServiceTypeManager(){}
	
	/**
	 * Method that registers a service type in system.
	 * Should mainly be called from the static block in this class.
	 * @param serviceType
	 */
	public static void registerServiceType(ServiceType serviceType){
		availableTypesByName.put(serviceType.getName(), serviceType);
		if(!serviceType.isCustom()){
			availableTypesByClassPath.put(serviceType.getClassPath(), serviceType);
		}
	}
	
	/**
	 * Method that removes a service type from the system
	 * 
	 */
	public static void deRegisterServiceType(ServiceType serviceType){
		String name = serviceType.getName();
		availableTypesByName.remove(name);
		if(!serviceType.isCustom()){
			availableTypesByClassPath.remove(serviceType.getClassPath());
		}
	}
	
	/**
	 * Returns the service type with the given name.
	 */
	public static ServiceType getServiceTypeByName(String name){
		return (ServiceType) availableTypesByName.get(name);
	}
	
	/**
	 * Returns the service type with the classpath or
	 * null if the classpath should have a custom page.
	 */
	public static ServiceType getServiceTypeByClassPath(String classPath){		
		return (ServiceType) availableTypesByClassPath.get(classPath);
	}
	
	/**
	 * @return returns all available workers in the GUI
	 */
	public static Collection getAvailableWorkerTypes(){
		return workerTypes;
	}
	
	
	
	
}

