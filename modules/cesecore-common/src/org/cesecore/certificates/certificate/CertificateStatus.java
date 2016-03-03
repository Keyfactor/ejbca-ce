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

package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.util.Date;

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;

/** Simple class encapsulating the certificate status information needed when making revocation checks.
 * 
 * @version $Id$
 */
public class CertificateStatus implements Serializable {

    private static final long serialVersionUID = 1515679904853388419L;
	
    public final static CertificateStatus REVOKED = new CertificateStatus("REVOKED", -1L, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    public final static CertificateStatus OK = new CertificateStatus("OK", -1L, RevokedCertInfo.NOT_REVOKED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    public final static CertificateStatus NOT_AVAILABLE = new CertificateStatus("NOT_AVAILABLE", -1L, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);

    private final String name;
    public final Date revocationDate;
    /** @see RevocationReasons */
    public final int revocationReason;
    public final int certificateProfileId;
    
    public CertificateStatus(String name, long date, int reason, int certProfileId ) {
        this.name = name;
        this.revocationDate = new Date(date);
        this.revocationReason = reason;
        this.certificateProfileId = certProfileId;
    }
    
    @Override
    public String toString() {
        return this.name;
    }
    
    @Override
    public boolean equals(Object obj) {
        return obj instanceof CertificateStatus && this.equals((CertificateStatus)obj);
    }
    
    public boolean equals(CertificateStatus obj) {
        return this.name.equals(obj.toString());
    }
    
    public boolean isRevoked() {
        return revocationReason != RevokedCertInfo.NOT_REVOKED && revocationReason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
    }
}
