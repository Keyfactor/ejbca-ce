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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;

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

