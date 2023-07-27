package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.annotations.ApiModelProperty;

public class CoapEstServerKeygenRestResponse {

    @ApiModelProperty
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
