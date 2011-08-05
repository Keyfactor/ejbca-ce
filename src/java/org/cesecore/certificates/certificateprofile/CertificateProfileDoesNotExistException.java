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
 * Based on EJBCA version: CertificateProfileDoesntExistsException.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id: CertificateProfileDoesNotExistException.java 168 2011-01-27 10:07:30Z mikek $
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
