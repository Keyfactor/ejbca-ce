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

package org.ejbca.ui.web.rest.api.types.response;

import org.ejbca.ui.web.rest.api.types.CertificateTypes;
import org.ejbca.ui.web.rest.api.types.ResponseStatus;

/**
 * A Response container for expiring certificate service.
 *
 * @version $Id: ExpiringCertificatesResponse.java 29010 2018-05-23 13:09:53Z jekaterina_b_helmes $
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
