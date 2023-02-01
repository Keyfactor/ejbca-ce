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

import io.swagger.annotations.ApiModelProperty;

public class SshCertificateRestResponse {
    @ApiModelProperty(value = "Certificate", example = "c3N...T09")
    private byte[] certificate;
    @ApiModelProperty(value = "Response format", example = "BYTE")
    private String responseFormat;

    public SshCertificateRestResponse() {
    }

    public SshCertificateRestResponse(byte[] certificate, String responseFormat) {
        this.certificate = certificate;
        this.responseFormat = responseFormat;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
    }

}
