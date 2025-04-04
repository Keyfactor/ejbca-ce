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
package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.certificate.CertificateConstants;

public enum RequestType {
    PUBLICKEY( CertificateConstants.CERT_REQ_TYPE_PUBLICKEY),
    CRMF( CertificateConstants.CERT_REQ_TYPE_CRMF),
    SPKAC( CertificateConstants.CERT_REQ_TYPE_SPKAC),
    CVC( CertificateConstants.CERT_REQ_TYPE_CVC),
    PKCS10( CertificateConstants.CERT_REQ_TYPE_PKCS10);

    private final int requestTypeValue;

    RequestType(final int requestTypeValue) {
        this.requestTypeValue = requestTypeValue;
    }

    public int getRequestTypeValue() {
        return requestTypeValue;
    }
    /**
     * Resolves the Request Type  using its name or returns null.
     *
     * @param name status name.
     * @return RequestType using its name or null.
     */
    public static RequestType resolveRequestTypeStatusByName(final String name) {
        for (RequestType requestType : values()) {
            if (requestType.name().equalsIgnoreCase(name)) {
                return requestType;
            }
        }
        return null;
    }
}
