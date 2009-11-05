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
 * An exception thrown when someone tries to change a certificate profile that doesn't already exits
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CertificateProfileDoesntExistsException extends EjbcaException {
    
    /**
     * Creates a new instance of <code>CertificateProfileDoesntExistsException</code> without detail message.
     */
    public CertificateProfileDoesntExistsException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
