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
 
package org.ejbca.core.model.ca.certificateprofiles;

import org.ejbca.core.EjbcaException;


/**
 * An exception thrown when someone tries to add a certificate profile that already exits
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CertificateProfileExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CertificateProfileExistsException</code> without detail message.
     */
    public CertificateProfileExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateProfileExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileExistsException(String msg) {
        super(msg);
    }
}
