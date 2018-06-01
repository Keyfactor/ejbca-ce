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
 * 
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
    
    public String getIssuerDn() {
        return issuerDn;
    }
    
    public String getSerialNumebr() {
        return serialNumber;
    }
    
    public String getStatus() {
        return status;
    }
    
    public String getReason() {
        return reason;
    }
    
    public Date getDate() {
        return revocationDate;
    }
}