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
import java.util.List;



/**
 * Class used mostly when creating service. Also used when info about the services 
 * is neesed
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class XKMSCAServiceInfo extends BaseSigningCAServiceInfo implements Serializable {    
                  
    /**
     * Used when creating new service.
     */
       
    public XKMSCAServiceInfo(int status,
                             String subjectdn, 
                             String subjectaltname, 
                             String keyspec, 
                             String keyalgorithm){
      super(status, subjectdn, subjectaltname, keyspec, keyalgorithm);                       	
    }
    
	/**
	 * Used when returning information from service
	 */       
    public XKMSCAServiceInfo(int status,
    		String subjectdn, 
    		String subjectaltname, 
    		String keyspec, 
    		String keyalgorithm,
    		List xkmscertchain) {
    	super(status, subjectdn, subjectaltname, keyspec, keyalgorithm, xkmscertchain);                       	
    }    
    
    /*
     * Used when updating existing services, only status is used.
     */
    public XKMSCAServiceInfo(int status, boolean renew){
      super(status, renew);	
    }
    
    public List getXKMSSignerCertificatePath(){ return super.getCertificatePath();}   

}
