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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.ejb.Local;


/**
 * Local interface for OcspResponseGeneratorSession
 */
@Local
public interface OcspResponseGeneratorSessionLocal extends OcspResponseGeneratorSession {



    void initTimers();

    /** One-time load and conversion of configured keystores to CryptoTokens and OcspKeyBindings */
    void adhocUpgradeFromPre60(char[] activationPassword);

    String healthCheck();

    /** @see org.cesecore.certificates.ocsp.cache.OcspRequestSignerStatusCache#flush() */
    void clearOcspRequestSignerRevocationStatusCache();

    /**
     * Pre-produces an OCSP response for the provided CA and serial number. The response will
     * be signed according to current OCSP Key Binding settings and OCSP config if applicable.
     *
     *  Expired certificates are ignored when creating or updating presigned OCSP responses, unless
     *  includeExpiredCertificates is selected on the Service level.
     *
     * @param cacert of the CA which signs the OCSP response
     * @param serialNr of the certificate to produce a response for.
     * @param presignResponseValidity causes the validity of the response to be set to 9999. WARNING: This should only be used in the ETSI EN 319 411-2 and -1 usecase. 
     * @param includeExpiredCertificates to include expired certificates in presigned OCSP responses
     * @param certIDHashAlgorithm of the certId
     */
    void preSignOcspResponse(X509Certificate cacert, BigInteger serialNr, PresignResponseValidity presignResponseValidity, boolean includeExpiredCertificates, String certIDHashAlgorithm);

}
