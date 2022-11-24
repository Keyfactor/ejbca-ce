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
 */
public class CertificateStatus implements Serializable {

    private static final long serialVersionUID = 1515679904853388419L;
	
    public static final CertificateStatus REVOKED = new CertificateStatus("REVOKED", -1L, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    public static final CertificateStatus OK = new CertificateStatus("OK", -1L, RevokedCertInfo.NOT_REVOKED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    public static final CertificateStatus NOT_AVAILABLE = new CertificateStatus("NOT_AVAILABLE", -1L, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, CertificateProfileConstants.CERTPROFILE_NO_PROFILE);

    private final String name;
    public final Date revocationDate;
    /** @see RevocationReasons */
    public final int revocationReason;
    public final int certificateProfileId;
    
    // relevant as expired certificate OCSP responses are not stored
    private long expirationDate;
    
    public CertificateStatus(String name, long date, int reason, int certProfileId ) {
        this.name = name;
        this.revocationDate = new Date(date);
        this.revocationReason = reason;
        this.certificateProfileId = certProfileId;
    }
    
    @Override
    public String toString() {
        return name;
    }
    
    @Override
    public boolean equals(Object obj) {
        return obj instanceof CertificateStatus && equals((CertificateStatus)obj);
    }
    
    public boolean equals(CertificateStatus obj) {
        return name.equals(obj.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
    
    public boolean isRevoked() {
        return revocationReason != RevokedCertInfo.NOT_REVOKED && revocationReason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL;
    }

    public long getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(long expirationDate) {
        this.expirationDate = expirationDate;
    }
}
