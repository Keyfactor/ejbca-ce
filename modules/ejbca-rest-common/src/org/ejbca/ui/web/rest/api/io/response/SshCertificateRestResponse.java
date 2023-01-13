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
