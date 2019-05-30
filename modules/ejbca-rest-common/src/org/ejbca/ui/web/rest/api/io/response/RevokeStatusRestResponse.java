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

import java.util.Date;

import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevocationReasons;

import com.fasterxml.jackson.annotation.JsonInclude;


/**
 * JSON output holder for certificate revocation status
 * @version $Id: RevokeStatusRestResponse.java 29405 2018-06-28 15:39:53Z bastianf $
 *
 */
public class RevokeStatusRestResponse {
    private String issuerDn;
    private String serialNumber;
    private boolean isRevoked;
    private String revocationReason;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date revocationDate;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String message;

    public RevokeStatusRestResponse() {}

    private RevokeStatusRestResponse(String issuerDn, String serialNumber, boolean revoked, String revocationReason, Date revocationDate, String message) {
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        this.isRevoked = revoked;
        this.revocationReason = revocationReason;
        this.revocationDate = revocationDate;
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

        public RevokeStatusRestResponseBuilder message(String message) {
            this.message = message;
            return this;
        }

        public RevokeStatusRestResponse build() {
            return new RevokeStatusRestResponse(issuerDn, serialNumber, isRevoked, revocationReason, revocationDate, message);
        }
    }

    public static class RevokeStatusRestResponseConverter {

        public RevokeStatusRestResponse toRestResponse(CertificateStatus certificateStatus, String issuerDn, String serialNumber) {
            return RevokeStatusRestResponse.builder().
                revoked(certificateStatus.isRevoked()).
                revocationReason(RevocationReasons.getFromDatabaseValue(certificateStatus.revocationReason).getStringValue()).
                revocationDate(certificateStatus.isRevoked() ? certificateStatus.revocationDate : null).
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
     * @return optional revocation message
     */
    public String getMessage() {
        return message;
    }
}