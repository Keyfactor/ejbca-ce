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
 * An exception thrown when someone tries to access a certificate profile that doesn't exist.
 *
 * @version $Id$
 */
public class CertificateProfileDoesNotExistException extends CesecoreException {
    
    private static final long serialVersionUID = -642610825885468919L;


    /**
     * Creates a new instance without detail message.
     */
    public CertificateProfileDoesNotExistException() {
        super();
    }
    
    
    /**
     * Constructs an instance with the specified detail message.
     * @param msg the detail message.
     */
    public CertificateProfileDoesNotExistException(String msg) {
        super(msg);
    }
}
