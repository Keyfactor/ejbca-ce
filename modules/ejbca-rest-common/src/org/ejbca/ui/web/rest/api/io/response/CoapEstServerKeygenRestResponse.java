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
