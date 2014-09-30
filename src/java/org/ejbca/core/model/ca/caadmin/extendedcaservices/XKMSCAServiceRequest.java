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

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.w3c.dom.Document;

/**
 * Class used when requesting XKMS related services from a CA.  
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class XKMSCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
	private static final long serialVersionUID = 5598850910793030599L;

    public static final Logger m_log = Logger.getLogger(XKMSCAServiceRequest.class);
	
    private Document doc = null;
    private String id = null;
    private boolean sign = false;
    private boolean encrypt = false;    

    
    /** Constructor for XKMSCAServiceRequest
     */                   
    public XKMSCAServiceRequest(Document doc, String id, boolean sign, boolean encrypt) {
        this.doc = doc;
        this.id = id;
        this.sign = sign;
        this.encrypt = encrypt; 
    }
    public Document getDoc() {
        return doc;
    }  
    public String getId(){
    	return id;
    }
    public boolean isSign() {
    	return sign;
    }
    public boolean isEncrypt() {
    	return encrypt;
    }
	@Override
	public int getServiceType() {
		return ExtendedCAServiceTypes.TYPE_XKMSEXTENDEDSERVICE;
	}



}
