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


import io.swagger.v3.oas.annotations.media.Schema;

public class CoapEstServerKeygenRestResponse {

    @Schema
    private byte[] enrolledCertificatePrivatekey;

    public CoapEstServerKeygenRestResponse(byte[] enrolledCertificatePrivatekey) {
        this.enrolledCertificatePrivatekey = enrolledCertificatePrivatekey;
    }

    public byte[] getEnrolledCertificatePrivatekey() {
        return enrolledCertificatePrivatekey;
    }

    public void setEnrolledCertificatePrivatekey(byte[] enrolledCertificatePrivatekey) {
        this.enrolledCertificatePrivatekey = enrolledCertificatePrivatekey;
    }
}
