/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
