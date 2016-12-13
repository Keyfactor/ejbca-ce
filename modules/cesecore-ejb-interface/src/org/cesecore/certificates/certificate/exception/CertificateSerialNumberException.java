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

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * Exception used in order to catch the error that we're trying to create a certificate that already exists.
 * 
 * @version $Id: CustomCertSerialNumberException.java 17625 2013-09-20 07:12:06Z netmackan $
 */
public class CertificateSerialNumberException extends CesecoreException {

    private static final long serialVersionUID = -2969078756967846634L;

    public CertificateSerialNumberException(String message) {
        super(message);
    }

    public CertificateSerialNumberException(Exception e) {
        super(e);
    }

    public CertificateSerialNumberException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}
