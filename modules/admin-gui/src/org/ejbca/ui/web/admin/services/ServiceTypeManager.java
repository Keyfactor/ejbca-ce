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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.admin.services.servicetypes.CRLDownloadWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CRLUpdateWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CertificateExpirationNotifierWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomActionType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.CustomWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.HsmKeepAliveWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.MailActionType;
import org.ejbca.ui.web.admin.services.servicetypes.NoActionType;
import org.ejbca.ui.web.admin.services.servicetypes.PeriodicalIntervalType;
import org.ejbca.ui.web.admin.services.servicetypes.PublishQueueWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.RenewCAWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.RolloverWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.ServiceType;
import org.ejbca.ui.web.admin.services.servicetypes.UserPasswordExpireWorkerType;
import org.ejbca.ui.web.admin.services.servicetypes.WorkerType;

/**
 * Central class managing available services types. New workers, actions, intervals
 * should be registered in the class in order to proved GUI to it.
 * 
 * To this there is also a need for a JSFSubView page with it's managed beans.
 *
 * @version $Id$
 */
public class ServiceTypeManager implements Serializable {
	
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
	private static final long serialVersionUID = -7328709803784066077L;

	private static Logger log = Logger.getLogger(ServiceTypeManager.class);
	
	// static variables common for the application
	private static HashMap<String, ServiceType> availableTypesByName = new HashMap<String, ServiceType>();
	private static HashMap<String, ServiceType> availableTypesByClassPath = new HashMap<String, ServiceType>();
	private static ArrayList<ServiceType> workerTypes = new ArrayList<ServiceType>();
	

	private HashMap<?, ?> localAvailableTypesByName;
	private HashMap<?, ?> localAvailableTypesByClassPath;
	private ArrayList<ServiceType> localWorkerTypes;
	
	static{
		ServiceTypeManager.registerServiceType(new CustomIntervalType());
		ServiceTypeManager.registerServiceType(new PeriodicalIntervalType());
		ServiceTypeManager.registerServiceType(new CustomActionType());
		ServiceTypeManager.registerServiceType(new NoActionType());	
		ServiceTypeManager.registerServiceType(new MailActionType());	
		ServiceTypeManager.registerServiceType(new CustomWorkerType());
        ServiceTypeManager.registerServiceType(new CRLDownloadWorkerType());
		ServiceTypeManager.registerServiceType(new CRLUpdateWorkerType());
		ServiceTypeManager.registerServiceType(new CertificateExpirationNotifierWorkerType());
		ServiceTypeManager.registerServiceType(new UserPasswordExpireWorkerType());
		ServiceTypeManager.registerServiceType(new RenewCAWorkerType());
		ServiceTypeManager.registerServiceType(new RolloverWorkerType());
		ServiceTypeManager.registerServiceType(new PublishQueueWorkerType());
		ServiceTypeManager.registerServiceType(new HsmKeepAliveWorkerType());
	}

	@SuppressWarnings("unchecked")
    public  ServiceTypeManager(){
		// Create a deep clone of the static global data.
		try{
		  ByteArrayOutputStream baos = new ByteArrayOutputStream();
		  ObjectOutputStream oos = new ObjectOutputStream(baos);
		  oos.writeObject(availableTypesByName);
		  oos.writeObject(availableTypesByClassPath);
		  oos.writeObject(workerTypes);
		  ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		  ObjectInputStream ois = new ObjectInputStream(bais);
		  localAvailableTypesByName = (HashMap<?, ?>) ois.readObject();
		  localAvailableTypesByClassPath = (HashMap<?, ?>) ois.readObject();
		  localWorkerTypes = (ArrayList<ServiceType>) ois.readObject();
		}catch(IOException e){
			log.error(e);
		} catch (ClassNotFoundException e) {
			log.error(e);
		}

		
	}
	
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
		if(serviceType instanceof WorkerType){
			workerTypes.add(serviceType);
		}
		
	}
	
	/**
	 * Returns the service type with the given name.
	 */
	public  ServiceType getServiceTypeByName(String name){
		return (ServiceType) localAvailableTypesByName.get(name);
	}
	
	/**
	 * Returns the service type with the classpath or
	 * null if the classpath should have a custom page.
	 */
	public ServiceType getServiceTypeByClassPath(String classPath){		
		return (ServiceType) localAvailableTypesByClassPath.get(classPath);
	}
	
	/**
	 * @return returns all available workers in the GUI
	 */
	public Collection<ServiceType> getAvailableWorkerTypes(){
		return localWorkerTypes;
	}
}

