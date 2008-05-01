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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.caadmin.CA;


/** 
 * ExtendedCAService base class.
 * 
 * @version $Id$
 */
public abstract class ExtendedCAService extends UpgradeableDataHashMap implements java.io.Serializable{
    
    public static final String EXTENDEDCASERVICETYPE = "extendedcaservicetype";

	public final String SERVICENAME = "";  	
		
	public static final String STATUS = "status";
	
	protected void setStatus(int status){ this.data.put(STATUS, new Integer(status)); }
	
	protected int getStatus(){ return ((Integer) data.get(STATUS)).intValue(); }
	
	/**
	 * Initializes the ExtendedCAService
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void init(CA ca) throws Exception;
	
	
	/**
	 * Update the ExtendedCAService data
	 * 
	 * @param info contains information used to activate the service.    
	 */
	public abstract void update(ExtendedCAServiceInfo info, CA ca) throws Exception;
			

	/** 
	 * Method used to retrieve information about the service.
	 */

    public abstract ExtendedCAServiceInfo getExtendedCAServiceInfo();

    /** 
     * Method used to perform the service.
     */
    public abstract ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) 
      throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException;

    
}
