package org.ejbca.ui.web.rest.api.types;

import java.util.List;

/**
 * A class representing general information about certificate.
 *
 *
 */
public class CertificateTypes {
    private List<CertificateType> certificates;

    public CertificateTypes(List<CertificateType> certificates) {
        this.certificates = certificates;
    }

    public List<CertificateType> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<CertificateType> certificates) {
        this.certificates = certificates;
    }
}
