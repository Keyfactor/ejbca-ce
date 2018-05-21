package org.ejbca.ui.web.rest.api.types.response;

import org.ejbca.ui.web.rest.api.types.CertificateTypes;
import org.ejbca.ui.web.rest.api.types.ResponseStatus;

/**
 * @author Jekaterina Bunina, Helmes AS, jekaterina.bunina@helmes.ee
 */
public class ExpiringCertificatesResponse {
    private ResponseStatus responseStatus;
    private CertificateTypes certificateTypes;

    public ExpiringCertificatesResponse(ResponseStatus responseStatus, CertificateTypes certificateTypes) {
        this.responseStatus = responseStatus;
        this.certificateTypes = certificateTypes;
    }

    public ResponseStatus getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(ResponseStatus responseStatus) {
        this.responseStatus = responseStatus;
    }

    public CertificateTypes getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(CertificateTypes certificateTypes) {
        this.certificateTypes = certificateTypes;
    }
}
