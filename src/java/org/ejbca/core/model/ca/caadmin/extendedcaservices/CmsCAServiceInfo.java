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
 
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;

/**
 * Class used mostly when creating service. Also used when info about the services 
 * is needed
 * 
 * @version $Id$
 */
public class CmsCAServiceInfo extends BaseSigningCAServiceInfo implements Serializable {    
       
    private static final long serialVersionUID = 7556251008892332034L;

    /** Used when creating new service. */
    public CmsCAServiceInfo(int status, String subjectdn, String subjectaltname, String keyspec,  String keyalgorithm) {
        super(status, subjectdn, subjectaltname, keyspec, keyalgorithm);                       	
    }
    
	/** Used when returning information from service. */
	public CmsCAServiceInfo(int status, String subjectdn, String subjectaltname, String keyspec, String keyalgorithm, List<Certificate> certchain) {
		super(status, subjectdn, subjectaltname, keyspec, keyalgorithm, certchain);                       	
	}    
    
    /* Used when updating existing services, only status is used. */
    public CmsCAServiceInfo(int status, boolean renew){
      super(status, renew);	
    }

	@Override
	public String getImplClass() {
		return CmsCAService.class.getName();
	}

	@Override
	public int getType() {
		return ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE;
	}
}
