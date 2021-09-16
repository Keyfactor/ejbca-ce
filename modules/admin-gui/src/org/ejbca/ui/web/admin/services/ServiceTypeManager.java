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
import org.ejbca.ui.web.admin.services.servicetypes.PreCertificateRevocationWorkerType;
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
 * should be registered in the class in order to provide GUI to it.
 * 
 * To this there is also a need for a JSFSubView page with it's managed beans.
 * 
 * This class currently hard-codes all classes, but could be rewritten to
 * use ServiceLoader if needed.
 *
 * @version $Id$
 */
public class ServiceTypeManager implements Serializable {

    private static final Logger log = Logger.getLogger(ServiceTypeManager.class);

	private static final long serialVersionUID = -7328709803784066077L;

	private final HashMap<String, ServiceType> availableTypesByName = new HashMap<>();
	private final HashMap<String, ServiceType> availableTypesByClassPath = new HashMap<>();
	private final ArrayList<ServiceType> workerTypes = new ArrayList<>();

    public ServiceTypeManager() {
        registerServiceType(new CustomIntervalType());
        registerServiceType(new PeriodicalIntervalType());
        registerServiceType(new CustomActionType());
        registerServiceType(new NoActionType()); 
        registerServiceType(new MailActionType());   
        registerServiceType(new CustomWorkerType());
        registerServiceType(new CRLDownloadWorkerType());
        registerServiceType(new CRLUpdateWorkerType());
        registerServiceType(new CertificateExpirationNotifierWorkerType());
        registerServiceType(new UserPasswordExpireWorkerType());
        registerServiceType(new RenewCAWorkerType());
        registerServiceType(new RolloverWorkerType());
        registerServiceType(new PublishQueueWorkerType());
        registerServiceType(new HsmKeepAliveWorkerType());
        // Enterprise Edition workers that don't use the custom worker framework
        final ServiceType[] eeWorkerTypes = { new PreCertificateRevocationWorkerType() };
        for (final ServiceType eeWorkerType : eeWorkerTypes) {
            final String classpath = eeWorkerType.getClassPath();
            try {
                Class.forName(classpath, false, getClass().getClassLoader()); // ensure class is available
                registerServiceType(eeWorkerType);
            } catch (ClassNotFoundException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Class " +  classpath + " is not available");
                }
            }
        }
	}
	
	/**
	 * Registers a service type in this instance. Called by the constructor.
	 * @param serviceType Service type to register
	 */
	private void registerServiceType(final ServiceType serviceType) {		
		availableTypesByName.put(serviceType.getName(), serviceType);
		if (!serviceType.isCustom()) {
			availableTypesByClassPath.put(serviceType.getClassPath(), serviceType);
		}
		if (serviceType instanceof WorkerType) {
			workerTypes.add(serviceType);
		}
	}
	
	/**
	 * Returns the service type with the given name.
	 */
	public ServiceType getServiceTypeByName(String name) {
		return availableTypesByName.get(name);
	}
	
	/**
	 * Returns the service type with the classpath or
	 * null if the classpath should have a custom page.
	 */
	public ServiceType getServiceTypeByClassPath(String classPath) {		
		return availableTypesByClassPath.get(classPath);
	}
	
	/**
	 * @return returns all available workers in the GUI
	 */
	public Collection<ServiceType> getAvailableWorkerTypes() {
		return workerTypes;
	}
}

