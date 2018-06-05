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