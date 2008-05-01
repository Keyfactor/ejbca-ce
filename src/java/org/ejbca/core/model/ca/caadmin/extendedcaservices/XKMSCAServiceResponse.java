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

import org.w3c.dom.Document;

/**
 * Class used when delevering XKMS service response from a CA.  
 *
 * @version $Id$
 */
public class XKMSCAServiceResponse extends ExtendedCAServiceResponse implements Serializable {    
                 
    private Document doc = null;
    
        
    public XKMSCAServiceResponse(Document doc) {
        this.doc = doc;        
    }    
           
    public Document getSignedDocument() { return this.doc; }
        
}
