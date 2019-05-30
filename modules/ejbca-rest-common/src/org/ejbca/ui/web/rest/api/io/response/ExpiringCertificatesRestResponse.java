/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.io.response;

/**
 * A Response container for expiring certificate service.
 *
 * @version $Id: ExpiringCertificatesRestResponse.java 29010 2018-05-23 13:09:53Z andrey_s_helmes $
 */
public class ExpiringCertificatesRestResponse {
    private PaginationRestResponseComponent paginationRestResponseComponent;
    private CertificatesRestResponse certificatesRestResponse;

    public ExpiringCertificatesRestResponse(PaginationRestResponseComponent paginationRestResponseComponent, CertificatesRestResponse certificatesRestResponse) {
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
