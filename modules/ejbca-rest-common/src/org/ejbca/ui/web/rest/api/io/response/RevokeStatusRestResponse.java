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

import java.util.Date;

import io.swagger.annotations.ApiModelProperty;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevocationReasons;

import com.fasterxml.jackson.annotation.JsonInclude;


/**
 * JSON output holder for certificate revocation status
 * @version $Id: RevokeStatusRestResponse.java 29405 2018-06-28 15:39:53Z bastianf $
 *
 */
public class RevokeStatusRestResponse {
    @ApiModelProperty(value = "Issuer Distinguished Name", example = "CN=ExampleCA")
    private String issuerDn;
    @ApiModelProperty(value = "Hex Serial Number", example = "1234567890ABCDEF")
    private String serialNumber;
    @ApiModelProperty(value = "Revokation status", example = "true")
    private boolean isRevoked;
    @ApiModelProperty(value = "RFC5280 revokation reason", example = "KEY_COMPROMISE")
    private String revocationReason;
    @ApiModelProperty(value = "Revokation date", example = "1970-01-01T00:00:00Z")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date revocationDate;
    @ApiModelProperty(value = "Invalidity date", example = "1970-01-01T00:00:00Z")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date invalidityDate;
    @ApiModelProperty(value = "Message", example = "Successfully revoked")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String message;

    public RevokeStatusRestResponse() {}

    private RevokeStatusRestResponse(String issuerDn, String serialNumber, boolean revoked, String revocationReason, Date revocationDate, Date invalidityDate, String message) {
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        this.isRevoked = revoked;
        this.revocationReason = revocationReason;
        this.revocationDate = revocationDate;
        this.invalidityDate = invalidityDate;
        this.message = message;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static RevokeStatusRestResponseBuilder builder() {
        return new RevokeStatusRestResponseBuilder();
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static RevokeStatusRestResponseConverter converter() {
        return new RevokeStatusRestResponseConverter();
    }

    public static class RevokeStatusRestResponseBuilder {
        private String issuerDn;
        private String serialNumber;
        private boolean isRevoked;
        private String revocationReason;
        private Date revocationDate;
        private Date invalidityDate;
        private String message;

        public RevokeStatusRestResponseBuilder issuerDn(String issuerDn) {
            this.issuerDn = issuerDn;
            return this;
        }

        public RevokeStatusRestResponseBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public RevokeStatusRestResponseBuilder revoked(boolean revoked) {
            this.isRevoked = revoked;
            return this;
        }

        public RevokeStatusRestResponseBuilder revocationReason(String reason) {
            this.revocationReason = reason;
            return this;
        }

        public RevokeStatusRestResponseBuilder revocationDate(Date revocationDate) {
            this.revocationDate = revocationDate;
            return this;
        }

        public RevokeStatusRestResponseBuilder invalidityDate(Date invalidityDate) {
            this.invalidityDate = invalidityDate;
            return this;
        }

        
        public RevokeStatusRestResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public RevokeStatusRestResponse build() {
            return new RevokeStatusRestResponse(issuerDn, serialNumber, isRevoked, revocationReason, revocationDate, invalidityDate, message);
        }
    }

    public static class RevokeStatusRestResponseConverter {

        public RevokeStatusRestResponse toRestResponse(CertificateStatus certificateStatus, String issuerDn, String serialNumber) {
            return RevokeStatusRestResponse.builder().
                revoked(certificateStatus.isRevoked()).
                revocationReason(RevocationReasons.getFromDatabaseValue(certificateStatus.revocationReason).getStringValue()).
                revocationDate(certificateStatus.isRevoked() ? certificateStatus.revocationDate : null).
                invalidityDate(certificateStatus.isRevoked() ? certificateStatus.invalidityDate : null).
                issuerDn(issuerDn).
                serialNumber(serialNumber).
                build();
        }
    }

    /**
     * @return subject DN of the certificates issuing CA
     */
    public String getIssuerDn() {
        return issuerDn;
    }

    /**
     * @return HEX encoded certificate serial number
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @return revocation status. "REVOKED" or "NOT REVOKED"
     */
    public boolean isRevoked() {
        return isRevoked;
    }

    /**
     * @return RFC5280 revocation reason or null of not revoked
     */
    public String getRevocationReason() {
        return revocationReason;
    }

    /**
     * @return revocation date or null of not revoked
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * @return invalidity date or null of not revoked
     */
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    
    /**
     * @return optional revocation message
     */
    public String getMessage() {
        return message;
    }
}