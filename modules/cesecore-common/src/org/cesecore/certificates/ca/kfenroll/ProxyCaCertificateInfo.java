/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.kfenroll;

import java.security.cert.X509Certificate;

/** Used by the proxy-ca module (available in specific editions of EJBCA only) */
public class ProxyCaCertificateInfo {
    
    private String certificateId;
    
    private String requestId; // forward compatibility to approval support via workflow api
    
    private X509Certificate clientCertificate;
    
    private String status;

    public ProxyCaCertificateInfo() {
    }

    public ProxyCaCertificateInfo(String certificateId, String requestId, X509Certificate clientCertificate, String status) {
        this.certificateId = certificateId;
        this.requestId = requestId;
        this.clientCertificate = clientCertificate;
        this.status = status;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public String getRequestId() {
        return requestId;
    }

    public X509Certificate getClientCertificate() {
        return clientCertificate;
    }

    public String getStatus() {
        return status;
    }

}
