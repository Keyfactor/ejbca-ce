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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.CertTools;

/**
 * Test session bean used to do some nasty manipulation on StandaloneOcspResponseGeneratorSessionBean
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspResponseGeneratorTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspResponseGeneratorTestSessionBean implements
        OcspResponseGeneratorTestSessionRemote, OcspResponseGeneratorTestSessionLocal {

    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    
    @Override
    public void replaceOcspSigningCache(List<X509Certificate> caCertificateChain, X509Certificate ocspSigningCertificate, PrivateKey privateKey,
            String signatureProviderName, InternalKeyBinding ocspKeyBinding) {
        OcspSigningCacheEntry ocspSigningCacheEntry = new OcspSigningCacheEntry(caCertificateChain.get(0), caCertificateChain, ocspSigningCertificate, privateKey,
                signatureProviderName, (OcspKeyBinding) ocspKeyBinding);
        try {
            OcspSigningCache.INSTANCE.stagingStart();
            OcspSigningCache.INSTANCE.stagingAdd(ocspSigningCacheEntry);
            OcspSigningCache.INSTANCE.stagingCommit(CertTools.getIssuerDN(ocspSigningCertificate));
        } finally {
            OcspSigningCache.INSTANCE.stagingRelease();
        }
    }
    
    @Override
    public List<X509Certificate> getCacheOcspCertificates() {
        final List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        for (OcspSigningCacheEntry entry : OcspSigningCache.INSTANCE.getEntries()) {
            certificates.add(entry.getFullCertificateChain().get(0));
        }
        return certificates;
    }
    @Override
    public void reloadOcspSigningCache() {
        ocspResponseGeneratorSession.reloadOcspSigningCache();
    }

}

