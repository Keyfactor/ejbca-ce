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
 * @version $Id:
 *
 */
public interface IOCSPLogger extends IPatternLogger {
    // OCSP Specific constants used by both AuditLogger and TransactionLogger
    static final String ISSUER_NAME_HASH = "ISSUER_NAME_HASH"; //Hash of the issuer DN
    static final String ISSUER_KEY = "ISSUER_KEY"; //The public key of the issuer of a requested certificate
    static final String SERIAL_NOHEX = "SERIAL_NOHEX"; // Serial number of the requested certificate.
    public static final String CLIENT_IP = "CLIENT_IP"; //IP of the client making the request
    public static final String STATUS = "STATUS"; //The status of the OCSP-Request. SUCCESSFUL = 0;MALFORMED_REQUEST = 1;INTERNAL_ERROR = 2;
}
