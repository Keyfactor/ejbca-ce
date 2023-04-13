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

/**
 * A class representing the response for EST simpleenroll and simplereenroll requests with CoAP REST method.
 * Used for communicating with CoAP Proxy
 *
 */
public class CoapEstEnrollRestResponse {

    @ApiModelProperty(value = "Enrolled Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private String enrolledCertificate;

    public CoapEstEnrollRestResponse(String enrolledCertificate) {
        this.enrolledCertificate = enrolledCertificate;
    }

    public String getEnrolledCertificate() {
        return enrolledCertificate;
    }

    public void setEnrolledCertificate(String enrolledCertificate) {
        this.enrolledCertificate = enrolledCertificate;
    }
}
