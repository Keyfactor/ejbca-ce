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
import org.cesecore.certificates.ocsp.cache.OcspRequestSignerStatusCacheSingletonLocal;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspRequestSignerStatusTestSessionBean implements OcspRequestSignerStatusTestSessionRemote {

    @EJB
    private OcspRequestSignerStatusCacheSingletonLocal ocspRequestSignerStatusCache;
    
    @Override
    public void flush() {
        ocspRequestSignerStatusCache.flush();
    }

    @Override
    public String createCacheLookupKey(String signercertIssuerName, BigInteger signercertSerNo) {
        return ocspRequestSignerStatusCache.createCacheLookupKey(signercertIssuerName, signercertSerNo);
    }

    @Override
    public void updateCachedCertificateStatus(String cacheLookupKey, CertificateStatus certificateStatus) {
        ocspRequestSignerStatusCache.updateCachedCertificateStatus(cacheLookupKey, certificateStatus);
        
    }

    @Override
    public CertificateStatus getCachedCertificateStatus(String cacheLookupKey) {
        return ocspRequestSignerStatusCache.getCachedCertificateStatus(cacheLookupKey);
    }

    
    
}
