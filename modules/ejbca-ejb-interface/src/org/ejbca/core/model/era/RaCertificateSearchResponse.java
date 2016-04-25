package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.certificate.CertificateDataWrapper;

/**
 * Response of certificates search from RA UI.
 * 
 * @version $Id$
 */
public class RaCertificateSearchResponse implements Serializable {
    
    // TODO: Make Externalizable instead to handle for future versioning

    private static final long serialVersionUID = 1L;

    private List<CertificateDataWrapper> cdws = new ArrayList<>();
    private boolean mightHaveMoreResults = false;

    public List<CertificateDataWrapper> getCdws() { return cdws; }
    public void setCdws(List<CertificateDataWrapper> cdws) { this.cdws = cdws; }

    public boolean isMightHaveMoreResults() { return mightHaveMoreResults; }
    public void setMightHaveMoreResults(boolean mightHaveMoreResults) { this.mightHaveMoreResults = mightHaveMoreResults; }
    
    public void merge(final RaCertificateSearchResponse other) {
        final Map<String,CertificateDataWrapper> cdwMap = new HashMap<>();
        for (final CertificateDataWrapper cdw : cdws) {
            cdwMap.put(cdw.getCertificateData().getFingerprint(), cdw);
        }
        for (final CertificateDataWrapper cdw : other.cdws) {
            cdwMap.put(cdw.getCertificateData().getFingerprint(), cdw);
        }
        this.cdws.clear();
        this.cdws.addAll(cdwMap.values());
        if (other.isMightHaveMoreResults()) {
            setMightHaveMoreResults(true);
        }
    }
}
