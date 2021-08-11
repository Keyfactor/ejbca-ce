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

package org.cesecore.certificates.ocsp.cache;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.cert.ocsp.CertificateID;

/**
 * OCSP Cache entry mapping CertificateId to CA Id for faster lookups of CA configuration 
 * @version $Id$
 */
public class OcspDataConfigCacheEntry {

    private final List<CertificateID> certificateID;
    private final int caId;
    private final boolean preProductionEnabled;
    private final boolean storeResponsesOnDemand;
    private final boolean isMsCaCompatible;

    public OcspDataConfigCacheEntry(X509Certificate issuerCertificate, int caId, boolean preProductionEnabled, boolean storeResponseOnDemand, boolean isMsCaCompatible) {
        certificateID = OcspDataConfigCache.getCertificateIdFromCertificate(issuerCertificate);
        this.caId = caId;
        this.preProductionEnabled = preProductionEnabled;
        this.storeResponsesOnDemand = storeResponseOnDemand;
        this.isMsCaCompatible = isMsCaCompatible;
    }
    
    public boolean isMsCaCompatible() {
        return isMsCaCompatible;
    }

    /** @return certificate ID of the CA that we want to respond for */
    public List<CertificateID> getCertificateID() { 
        return certificateID; 
    }

    /** @return caId of the CA that we want to respond for */
    public int getCaId() {
        return caId;
    }

    /** @return true if OCSP response pre-production is enabled for this issuing CA related to this CertificateId */
    public boolean isPreProductionEnabled() {
        return preProductionEnabled;
    }
    
    /** @return true if OCSP response should be stored upon request */
    public boolean isStoreResponseOnDemand() {
        return preProductionEnabled && storeResponsesOnDemand;
    }
    
}
