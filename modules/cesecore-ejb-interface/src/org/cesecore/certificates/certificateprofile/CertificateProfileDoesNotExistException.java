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
package org.cesecore.certificates.certificateprofile;

import org.cesecore.CesecoreException;


/**
 * An exception thrown when someone tries to change a certificate profile that doesn't already exits
 *
 * @version $Id$
 */
public class CertificateProfileDoesNotExistException extends CesecoreException {
    
    private static final long serialVersionUID = -642610825885468919L;


    /**
     * Creates a new instance of <code>CertificateProfileDoesntExistsException</code> without detail message.
     */
    public CertificateProfileDoesNotExistException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CertificateProfileDoesntExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileDoesNotExistException(String msg) {
        super(msg);
    }
}
