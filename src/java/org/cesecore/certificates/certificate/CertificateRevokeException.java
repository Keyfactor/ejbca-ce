/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import javax.ejb.ApplicationException;

import org.cesecore.CesecoreException;

/** Thrown if there is an error revoking a certificate, causes rollback.
 *  
 * @version $Id: CertificateRevokeException.java 435 2011-03-04 13:41:15Z tomas $
 */
@ApplicationException(rollback=true)  
public class CertificateRevokeException extends CesecoreException {

    private static final long serialVersionUID = 1L;
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public CertificateRevokeException(String message) {
        super(message);
    }
    /**
     * Constructs an instance of <code>IllegalKeyException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CertificateRevokeException(Exception e) {
        super(e);
    }
}
