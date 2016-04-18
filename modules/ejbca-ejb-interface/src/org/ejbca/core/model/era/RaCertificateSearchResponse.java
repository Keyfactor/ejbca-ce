package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateDataWrapper;

/**
 * Response of certificates search from RA UI.
 * 
 * @version $Id$
 */
public class RaCertificateSearchResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<CertificateDataWrapper> cdws = new ArrayList<>();
    private boolean mightHaveMoreResults = false;

    public List<CertificateDataWrapper> getCdws() { return cdws; }
    public void setCdws(List<CertificateDataWrapper> cdws) { this.cdws = cdws; }

    public boolean isMightHaveMoreResults() { return mightHaveMoreResults; }
    public void setMightHaveMoreResults(boolean mightHaveMoreResults) { this.mightHaveMoreResults = mightHaveMoreResults; }
    
    public void merge(final RaCertificateSearchResponse other) {
        this.cdws.addAll(other.getCdws());
        if (other.isMightHaveMoreResults()) {
            setMightHaveMoreResults(true);
        }
    }
}
