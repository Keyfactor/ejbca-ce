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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

import org.ejbca.core.model.services.workers.RenewCAWorker;

/**
 * Class managing the view of the Renew CA Worker
 * 
 * @author Tomas Gustavsson
 *
 * @version $Id$
 */
public class RenewCAWorkerType extends BaseEmailNotifyingWorkerType {
	private static final long serialVersionUID = 2L;
	
	public static final String NAME = "RENEWCAWORKER";

	private static final String RENEWCAWORKER_SUB_PAGE = "renewcaworker.xhtml";
	
	private boolean renewkeys = false;	

	public RenewCAWorkerType(){
		super(NAME, RENEWCAWORKER_SUB_PAGE, RenewCAWorker.class.getName());
	}
	
	public boolean isRenewKeys() {
		return renewkeys;
	}
	public void setRenewKeys(boolean renewkeys) {
		this.renewkeys = renewkeys;
	}
	
	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties
	 */
	@Override
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {
		Properties ret = super.getProperties(errorMessages);
		if(renewkeys){
			ret.setProperty(RenewCAWorker.PROP_RENEWKEYS, "TRUE");
		} else {
			ret.setProperty(RenewCAWorker.PROP_RENEWKEYS, "FALSE");			
		}
		return ret;
	}
	
	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	@Override
	public void setProperties(Properties properties) throws IOException {
		super.setProperties(properties);
		renewkeys = properties.getProperty(RenewCAWorker.PROP_RENEWKEYS,"").equalsIgnoreCase("TRUE");
	}

}
