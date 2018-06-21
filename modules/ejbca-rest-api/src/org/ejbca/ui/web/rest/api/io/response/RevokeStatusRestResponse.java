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


/**
 * JSON output holder for certificate revocation status
 * @version $Id$
 *
 */
public class RevokeStatusRestResponse {

    private String issuerDn;
    private String serialNumber;
    private String status;
    private String reason;
    private Date revocationDate;
    
    public RevokeStatusRestResponse() {}
    
    /**
     * @param certificateStatus result of revocation status lookup
     * @param issuerDn subject DN of the certificates issuing CA
     * @param serialNumber HEX formated without prefix
     */
    public RevokeStatusRestResponse(CertificateStatus certificateStatus, String issuerDn, String serialNumber) {
        this.issuerDn = issuerDn;
        this.serialNumber = serialNumber;
        if (certificateStatus.isRevoked()) {
            this.status = "REVOKED";
        } else {
            this.status = "NOT REVOKED";
        }
        this.reason = RevocationReasons.getFromDatabaseValue(certificateStatus.revocationReason).getStringValue();
        // Formated by JsonDateSerializer
        this.revocationDate = certificateStatus.revocationDate;
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
    public String getReason() {
        return reason;
    }
    
    /**
     * @return revocation date or null of not revoked
     */
    public Date getDate() {
        return revocationDate;
    }
}