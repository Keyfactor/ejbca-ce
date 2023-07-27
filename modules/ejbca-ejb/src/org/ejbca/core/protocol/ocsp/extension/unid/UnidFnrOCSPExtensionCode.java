/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp.extension.unid;

/**
 * 
 * @version $Id$
 *
 */
public enum UnidFnrOCSPExtensionCode {
    
    ERROR_NO_ERROR(0),
    ERROR_UNKNOWN(1),
    ERROR_UNAUTHORIZED(2),
    ERROR_NO_FNR_MAPPING(3),
    ERROR_NO_SERIAL_IN_DN(4),
    ERROR_SERVICE_UNAVAILABLE(5),
    ERROR_CERT_REVOKED(6);
    
    private final int errorCode;
    private UnidFnrOCSPExtensionCode(final int errorCode) {
        this.errorCode = errorCode;
    }

    public int getValue() {
        return errorCode;
    }

}
