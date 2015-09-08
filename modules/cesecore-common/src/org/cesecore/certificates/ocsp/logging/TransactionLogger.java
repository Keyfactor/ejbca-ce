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

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.config.OcspConfiguration;

/**
 * TODO: DOCUMENT ME.
 * 
 * @version $Id$
 *
 */
public class TransactionLogger extends PatternLogger {

    private static final long serialVersionUID = 1722398387512931482L;
    /**
     * The Common Name (CN) of the client making the request
     */
    public static final String REQ_NAME = "REQ_NAME";
    /**
     * DN of the issuer of the certificate used to sign the request.
     */
    public static final String SIGN_ISSUER_NAME_DN = "SIGN_ISSUER_NAME_DN";
    /**
     * Subject Name of the certificate used to sign the request.
     */
    public static final String SIGN_SUBJECT_NAME = "SIGN_SUBJECT_NAME";
    /**
     * Certificate serial number of the certificate used to sign the request.
     */
    public static final String SIGN_SERIAL_NO = "SIGN_SERIAL_NO";
    /**
     * The subject DN of the issuer of a requested certificate
     */
    public static final String ISSUER_NAME_DN = "ISSUER_NAME_DN";
    
    /**
     * Algorithm used by requested certificate to hash issuer key and issuer name
     */
    public static final String DIGEST_ALGOR = "DIGEST_ALGOR";
    
    /**
     * The number of certificates to check revocation status for
     */
    public static final String NUM_CERT_ID = "NUM_CERT_ID";

    /**
     * The requested certificate revocation status.
     */
    public static final String CERT_STATUS = "CERT_STATUS";
    
    /** The id of the certificate profile that was used to issue the requested certificate. */
    public static final String CERT_PROFILE_ID = "CERT_PROFILE_ID";

    /** The HTTP X-Forwarded-For header value. */
    public static final String FORWARDED_FOR = "FORWARDED_FOR";

    public TransactionLogger(Integer logId, String sessionId, String clientIp) {
        super( OcspConfiguration.getTransactionLog(), TransactionLogger.class, OcspConfiguration.getTransactionLogPattern(), OcspConfiguration.getTransactionLogOrder(), OcspConfiguration.getLogDateFormat(), OcspConfiguration.getLogTimeZone());
        
        paramPut(PatternLogger.LOG_ID, logId);
        paramPut(PatternLogger.SESSION_ID, sessionId);
        paramPut(PatternLogger.CLIENT_IP, clientIp);
        
        paramPut(PatternLogger.STATUS, "0");
        paramPut(REQ_NAME, "0");
        paramPut(SIGN_ISSUER_NAME_DN, "0");
        paramPut(SIGN_SUBJECT_NAME, "0");
        paramPut(SIGN_SERIAL_NO, "0");
        paramPut(NUM_CERT_ID, "0");
        paramPut(ISSUER_NAME_DN, "0");
        paramPut(PatternLogger.ISSUER_NAME_HASH, "0");
        paramPut(PatternLogger.ISSUER_KEY, "0");
        paramPut(DIGEST_ALGOR, "0");
        paramPut(PatternLogger.SERIAL_NOHEX, "0");
        paramPut(CERT_STATUS, "0");
        paramPut(PatternLogger.PROCESS_TIME, "-1");
        paramPut(CERT_PROFILE_ID, String.valueOf(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
        paramPut(FORWARDED_FOR, "");
    }
}
