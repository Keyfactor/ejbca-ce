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
 * A class representing general information about crl.
 *
 * version $Id: CaRestResource.java 29283 2018-06-19 12:25:27Z jekaterina_b_helmes $
 */
public class CrlRestResponse {

    @ApiModelProperty(value = "Certificate Revokation List (CRL)", example = "MIIEV...SqQPE")
    private byte[] crl;
    @ApiModelProperty(value = "Response format", example = "DER")
    private String responseFormat;

    private CrlRestResponse(byte[] certificate, String responseFormat) {
        this.crl = certificate;
        this.responseFormat = responseFormat;
    }

    public byte[] getCrl() {
        return crl;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CrlRestResponseBuilder builder() {
        return new CrlRestResponseBuilder();
    }


    public static class CrlRestResponseBuilder{
        private byte[] crl;
        private String responseFormat;

        public CrlRestResponseBuilder() {
        }

        public CrlRestResponseBuilder setCrl(byte[] crl) {
            this.crl = crl;
            return this;
        }

        public CrlRestResponseBuilder setResponseFormat(String responseFormat) {
            this.responseFormat = responseFormat;
            return this;
        }

        public CrlRestResponse build() {
            return new CrlRestResponse(crl, responseFormat);
        }
    }
}
