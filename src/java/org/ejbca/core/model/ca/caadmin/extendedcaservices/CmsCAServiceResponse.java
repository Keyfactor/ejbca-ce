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
 * Class used when delevering CMS service response from a CA.  
 *
 * @version $Id: CmsCAServiceResponse.java,v 1.1 2006-12-27 11:13:56 anatom Exp $
 */
public class CmsCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
                 
    private byte[] doc = null;
    
        
    public CmsCAServiceResponse(byte[] doc) {
        this.doc = doc;        
    }    
           
    public byte[] getCmsDocument() { return this.doc; }
        
}
