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
package org.cesecore.certificates.certificate.exception;

import com.keyfactor.CesecoreException;

/**
 * Exception used in order to catch the error that we are trying to use custom certificate serial numbers, but are not using a unique
 * issuerDN/certSerialNo index in the database. This index is needed in order to use custom certificate serial numbers.
 * 
 * @version $Id$
 */
public class CustomCertificateSerialNumberException extends CesecoreException {

    private static final long serialVersionUID = -2969078756967846634L;

    public CustomCertificateSerialNumberException(String message) {
        super(message);
    }

    public CustomCertificateSerialNumberException(Exception e) {
        super(e);
    }
}
