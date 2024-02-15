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
package org.ejbca.core.ejb.ocsp;

import java.security.cert.X509Certificate;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;

/** 
 * This interface is used to generate OCSP responses.
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#OCSP_Response_Generation}
 *
 */
public interface OcspResponseGeneratorSession {

    /**
     * This method delivers an OCSP response to a given request, as provided in the byte[] parameter.
     * @param requestBytes a byte array representing an encoded OCSPRequest.
     * @param requestCertificates An array of Certificates from the original HttpServletRequest
     * @param remoteAddress Remote address, most likely extracted from the HttpServletRequest
     * @param xForwardedFor Value of X-Forwarded-For header if it was present in the request.
     * @param auditLogger The AuditLogger to use for this transaction
     * @param transactionLogger The TransactionLogger to use for this transaction
     * @param isPreSigning true if we're using the method to presign responses.
     * @param preResponseValidity should normally be retrieved from configuration, but for eIDAS use cases may be set unlimited. USE WITH CAUTION. 
     * @param includeExpiredCertificates true to get responses for expired certificates with presigning.
     * @return a signed and encoded OCSPResponse wrapped in an OcspResponseInformation object
     * @throws MalformedRequestException if the request byte array was invalid.
     * @throws OCSPException if OCSP response generation fails
     */
    OcspResponseInformation getOcspResponse(byte[] requestBytes, X509Certificate[] requestCertificates, String remoteAddress,
                                            String xForwardedFor, StringBuffer requestUrl, AuditLogger auditLogger, TransactionLogger transactionLogger,
                                            boolean isPreSigning, PresignResponseValidity preResponseValidity , boolean includeExpiredCertificates) throws MalformedRequestException, OCSPException;
    
    /** Reloads the cache of OCSP signers. */
    void reloadOcspSigningCache();
    
    /** Reloads the cache of OCSP extensions (including extension specific caches, e.g. the CT OCSP response extensions cache). */
    void reloadOcspExtensionsCache();

    /** Clears CT fail fast cache. If CT is not supported in this build, then it does nothing. */
    void clearCTFailFastCache();
}
