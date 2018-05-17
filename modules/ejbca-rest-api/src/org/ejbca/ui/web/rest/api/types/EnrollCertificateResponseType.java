package org.ejbca.ui.web.rest.api.types;

public class EnrollCertificateResponseType {
        
    private String certificate;

    public EnrollCertificateResponseType(String certificate) {
        this.certificate = certificate;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
}