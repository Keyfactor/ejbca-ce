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
package org.cesecore.certificates.ocsp.logging;

import org.cesecore.config.OcspConfiguration;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 * 
 */
public class AuditLogger extends PatternLogger {
    
    private static final long serialVersionUID = 4474243795289459488L;
    /**
     * The byte[] ocsp-request that came with the http-request
     */
    public static final String OCSPREQUEST = "OCSPREQUEST";
    /**
     * The byte[] ocsp-response that was included in the http-response
     */
    public static final String OCSPRESPONSE = "OCSPRESPONSE";

    public AuditLogger(String ocspRequest, Integer logId, String sessionId, String clientIp) {
        super(OcspConfiguration.getAuditLog(), OcspConfiguration.getAuditLogPattern(), OcspConfiguration.getAuditLogOrder(), OcspConfiguration.getLogDateFormat(), OcspConfiguration.getLogTimeZone());

        paramPut(OCSPREQUEST, ocspRequest);
        paramPut(PatternLogger.LOG_ID, logId);
        paramPut(PatternLogger.SESSION_ID, sessionId);
        paramPut(PatternLogger.CLIENT_IP, clientIp);
        
        paramPut(PatternLogger.CLIENT_IP, "0");
        paramPut(OCSPREQUEST, "0");
        paramPut(OCSPRESPONSE, "0");
        paramPut(PatternLogger.STATUS, "-1");
        paramPut(PatternLogger.PROCESS_TIME, "-1");
    }

}
