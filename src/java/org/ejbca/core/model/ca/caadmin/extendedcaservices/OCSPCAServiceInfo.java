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

import java.io.Serializable;

/**
 * Class used mostly when creating service. Also used when info about the services 
 * is needed
 * 
 * The certificate path is set per request for the OCSP CA Service.
 * 
 * @version $Id$
 */
public class OCSPCAServiceInfo extends BaseSigningCAServiceInfo implements Serializable {    
       
    /** Used when creating new service and when returning information from service. */
    public OCSPCAServiceInfo(int status) {
    	super(status, null, null, null, null);                       	
    }

	@Override
	public String getImplClass() {
		return OCSPCAService.class.getName();
	}

	@Override
	public int getType() {
		return ExtendedCAServiceInfo.TYPE_OCSPEXTENDEDSERVICE;
	}
}
