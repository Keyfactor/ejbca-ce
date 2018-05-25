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

package org.ejbca.ui.web.rest.api.io.response;

/**
 * A Response container for expiring certificate service.
 *
 * @version $Id: ExpiringCertificatesResponse.java 29010 2018-05-23 13:09:53Z jekaterina_b_helmes $
 */
public class ExpiringCertificatesResponse {
    private PaginationRestResponseComponent paginationRestResponseComponent;
    private CertificatesRestResponse certificatesRestResponse;

    public ExpiringCertificatesResponse(PaginationRestResponseComponent paginationRestResponseComponent, CertificatesRestResponse certificatesRestResponse) {
        this.paginationRestResponseComponent = paginationRestResponseComponent;
        this.certificatesRestResponse = certificatesRestResponse;
    }

    public PaginationRestResponseComponent getPaginationRestResponseComponent() {
        return paginationRestResponseComponent;
    }

    public void setPaginationRestResponseComponent(PaginationRestResponseComponent paginationRestResponseComponent) {
        this.paginationRestResponseComponent = paginationRestResponseComponent;
    }

    public CertificatesRestResponse getCertificatesRestResponse() {
        return certificatesRestResponse;
    }

    public void setCertificatesRestResponse(CertificatesRestResponse certificatesRestResponse) {
        this.certificatesRestResponse = certificatesRestResponse;
    }
}
