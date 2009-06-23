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

package org.ejbca.core.protocol.ocsp;

import org.ejbca.util.IPatternLogger;

/**
 * OCSP Specific constants used by both {@link org.ejbca.core.protocol.ocsp.IAuditLogger} and {@link org.ejbca.core.protocol.ocsp.ITransactionLogger}
 * @version $Id:
 *
 */
public interface IOCSPLogger extends IPatternLogger {
    /**
     * Hash of the issuer DN
     */
    static final String ISSUER_NAME_HASH = "ISSUER_NAME_HASH";
    /**
     * The public key of the issuer of a requested certificate
     */
    static final String ISSUER_KEY = "ISSUER_KEY";
    /**
     * Serial number of the requested certificate.
     */
    static final String SERIAL_NOHEX = "SERIAL_NOHEX";
    /**
     * IP of the client making the request
     */
    static final String CLIENT_IP = "CLIENT_IP";
    /**
     * The status of the OCSP-Request. SUCCESSFUL = 0;MALFORMED_REQUEST = 1;INTERNAL_ERROR = 2;
     */
    static final String STATUS = "STATUS";
}
