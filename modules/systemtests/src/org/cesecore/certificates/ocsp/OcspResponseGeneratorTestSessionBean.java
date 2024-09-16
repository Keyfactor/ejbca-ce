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
package org.cesecore.certificates.ocsp;

import java.util.ArrayList;
import java.util.List;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;

import com.keyfactor.util.EJBTools;
import com.keyfactor.util.certificate.CertificateWrapper;

/**
 * Test session bean used to do some nasty manipulation on StandaloneOcspResponseGeneratorSessionBean
 * 
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspResponseGeneratorTestSessionBean implements
        OcspResponseGeneratorTestSessionRemote, OcspResponseGeneratorTestSessionLocal {

    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    
    @Override
    public List<CertificateWrapper> getCacheOcspCertificates() {
        final List<CertificateWrapper> certificates = new ArrayList<>();
        for (OcspSigningCacheEntry entry : OcspSigningCache.INSTANCE.getEntries()) {
            certificates.add(EJBTools.wrap(entry.getFullCertificateChain().get(0)));
        }
        return certificates;
    }
    @Override
    public void reloadOcspSigningCache() {
        ocspResponseGeneratorSession.reloadOcspSigningCache();
    }

}

