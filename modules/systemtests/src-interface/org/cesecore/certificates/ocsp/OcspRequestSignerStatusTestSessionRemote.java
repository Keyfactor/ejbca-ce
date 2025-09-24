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
package org.cesecore.certificates.ocsp;

import java.math.BigInteger;

import org.cesecore.certificates.certificate.CertificateStatus;

import jakarta.ejb.Remote;

/**
 * Allows for system testing of the OcspRequestSignerStatusCache singleton bean
 */
@Remote
public interface OcspRequestSignerStatusTestSessionRemote {

    void flush();
    
    String createCacheLookupKey(final String signercertIssuerName, final BigInteger signercertSerNo);
    
    void updateCachedCertificateStatus(final String cacheLookupKey, final CertificateStatus certificateStatus);
    
    CertificateStatus getCachedCertificateStatus(final String cacheLookupKey);
}
