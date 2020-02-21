package org.cesecore.certificates.ocsp.cache;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.cert.ocsp.CertificateID;

/**
 * OCSP Cache entry mapping CertificateId to CA Id for faster lookups of CA configuration 
 * @version $Id$
 *
 */
public class OcspPreProductionConfigCacheEntry {

    private final List<CertificateID> certificateID;
    private final int caId;
    private final boolean preProducionEnabled;
    
    public OcspPreProductionConfigCacheEntry(X509Certificate issuerCertificate, int caId, boolean preProductionEnabled) {
        certificateID = OcspPreProductionConfigCache.getCertificateIDFromCertificate(issuerCertificate);
        this.caId = caId;
        this.preProducionEnabled = preProductionEnabled;
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
    public boolean isPreProducionEnabled() {
        return preProducionEnabled;
    }
    
}
