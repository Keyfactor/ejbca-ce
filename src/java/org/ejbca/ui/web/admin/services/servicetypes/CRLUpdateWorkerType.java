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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

/**
 * @author Philip Vendil
 *
 * $id$
 */
public class CRLUpdateWorkerType extends WorkerType {
	
	
	public static final String NAME = "CRLUPDATEWORKER";
	
	private Collection compatibleActionTypeNames = new ArrayList();
	private Collection compatibleIntervalTypeNames = new ArrayList();
	
	private transient Properties properties = new Properties();
	
	public CRLUpdateWorkerType() {
		super("crlupdateworker.jsp", NAME, true);
		
		compatibleActionTypeNames.add(NoActionType.NAME);
		
		compatibleIntervalTypeNames.add(PeriodicalIntervalType.NAME);
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleActionTypeNames()
	 */
	public Collection getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleIntervalTypeNames()
	 */
	public Collection getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}

	/**
	 * 
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getClassPath()
	 */
	public String getClassPath() {		
		return "org.ejbca.core.model.services.workers.CRLUpdateWorker";
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties(ArrayList errorMessages) throws IOException {		
		return properties;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#isCustom()
	 */
	public boolean isCustom() {		
		return false;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {
		this.properties = properties;
	}

}
