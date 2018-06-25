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
 * @version $Id$
 *
 */
public class RevokeStatusRestResponse {

    public static final String STATUS_REVOKED       = "Revoked";
    public static final String STATUS_NOT_REVOKED   = "Not Revoked";
    
    private String issuerDn;
    private String serialNumber;
    private String status;
    private String revocationReason;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Date revocationDate;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String message;
    
    public RevokeStatusRestResponse() {}
    
    private RevokeStatusRestResponse(String issuerDn, String serialNumber, String status, String revocationReason, Date revocationDate, String message) {
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        this.status = status;
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
        private String status;
        private String revocationReason;
        private Date revocationDate;
        private String message;
        
        RevokeStatusRestResponseBuilder() {}

        public RevokeStatusRestResponseBuilder issuerDn(String issuerDn) {
            this.issuerDn = issuerDn;
            return this;
        }

        public RevokeStatusRestResponseBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public RevokeStatusRestResponseBuilder status(String status) {
            this.status = status;
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
            return new RevokeStatusRestResponse(issuerDn, serialNumber, status, revocationReason, revocationDate, message);
        }
    }
    
    public static class RevokeStatusRestResponseConverter {
        
        public RevokeStatusRestResponse toRestResponse(CertificateStatus certificateStatus, String issuerDn, String serialNumber) {
            return RevokeStatusRestResponse.builder().
                status(certificateStatus.isRevoked() ? STATUS_REVOKED : STATUS_NOT_REVOKED).
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
    public String getStatus() {
        return status;
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