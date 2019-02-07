/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import javax.ejb.ApplicationException;
import javax.xml.ws.WebFault;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;


/**
 * An exception thrown when someone tries to activate the CMS Service for a CA that does not have a CMS certificate path
 *
 */
@WebFault
@ApplicationException(rollback=true)
public class CmsCertificatePathMissingException extends CesecoreException {
    
    private static final long serialVersionUID = 1542504214401684378L;

    /**
     * Creates a new instance of <code>CmsCertificatePathMissingException</code> without detail message.
     */
    public CmsCertificatePathMissingException() {
        super(ErrorCode.CMS_CERTIFICATE_PATH_MISSING);
    }
        
    /**
     * Constructs an instance of <code>CmsCertificatePathMissingException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CmsCertificatePathMissingException(String msg) {
        super(ErrorCode.CMS_CERTIFICATE_PATH_MISSING, msg);
    }

    /**
     * Constructs an instance of <code>CmsCertificatePathMissingException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CmsCertificatePathMissingException(Exception e) {
        super(e);
    }
}
