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

import org.apache.log4j.Logger;

/**
 * Class used when requesting CMS related services from a CA.  
 *
 * @version $Id: CmsCAServiceRequest.java,v 1.1 2006-12-27 11:13:55 anatom Exp $
 */
public class CmsCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
	public static final Logger m_log = Logger.getLogger(CmsCAServiceRequest.class);
	
    private byte[] doc = null;
    private boolean sign = false;
    private boolean encrypt = false;    

    
    /** Constructor
     */                   
    public CmsCAServiceRequest(byte[] doc, boolean sign, boolean encrypt) {
        this.doc = doc;
        this.sign = sign;
        this.encrypt = encrypt; 
    }
    public byte[] getDoc() {
        return doc;
    }  
    public boolean isSign() {
    	return sign;
    }
    public boolean isEncrypt() {
    	return encrypt;
    }
}
