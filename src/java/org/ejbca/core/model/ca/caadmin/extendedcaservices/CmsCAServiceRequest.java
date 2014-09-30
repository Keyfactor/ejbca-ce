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

/**
 * Class used when requesting CMS related services from a CA.  
 *
 * @version $Id$
 */
public class CmsCAServiceRequest extends ExtendedCAServiceRequest implements Serializable {    
    
	public static final Logger m_log = Logger.getLogger(CmsCAServiceRequest.class);
	
	public static final int MODE_SIGN    = 1;
	public static final int MODE_ENCRYPT = 2;
	public static final int MODE_DECRYPT = 4;
	
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -762331405718560161L;
	
    private byte[] doc = null;
    private int mode = 0;
    
    /** Constructor
     * 
     * @param doc the data to process
     * @param mode, one of the MODE_ constants
     */                   
    public CmsCAServiceRequest(byte[] doc, int mode) {
        this.doc = doc;
        this.mode = mode;
    }
    public byte[] getDoc() {
        return doc;
    }  
    public int getMode() {
    	return mode;
    }
	@Override
	public int getServiceType() {
		return ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE;
	}
    
    
}
