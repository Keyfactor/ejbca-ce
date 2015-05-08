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

import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Helper for building certificate status object from raw database meta data.
 * 
 * @version $Id$
 */
public abstract class CertificateStatusHelper {

    /**
     * Algorithm: 
     * If status is CERT_REVOKED the certificate is revoked and reason and date is picked up.
     * If status is CERT_ARCHIVED and reason is _NOT_ REMOVEFROMCRL or NOT_REVOKED the certificate is revoked and reason and date is picked up.
     * If status is CERT_ARCHIVED and reason is REMOVEFROMCRL or NOT_REVOKED the certificate is NOT revoked.
     * If status is neither CERT_REVOKED or CERT_ARCHIVED the certificate is NOT revoked
     * 
     * @return CertificateStatus, can be compared (==) with CertificateStatus.OK, CertificateStatus.REVOKED and CertificateStatus.NOT_AVAILABLE
     */
    public static CertificateStatus getCertificateStatus(final CertificateData certificateData) {
        if (certificateData == null) {
            return CertificateStatus.NOT_AVAILABLE;
        }
        final int pId;
        {
            final Integer tmp = certificateData.getCertificateProfileId();
            pId = tmp != null ? tmp.intValue() : CertificateProfileConstants.CERTPROFILE_NO_PROFILE;
        }
        final int status = certificateData.getStatus();
        if (status == CertificateConstants.CERT_REVOKED) {
            return new CertificateStatus(certificateData.getRevocationDate(), certificateData.getRevocationReason(), pId);
        }
        if (status != CertificateConstants.CERT_ARCHIVED) {
            return new CertificateStatus(CertificateStatus.OK.toString(), pId);
        }
        // If the certificate have status ARCHIVED, BUT revocationReason is REMOVEFROMCRL or NOTREVOKED, the certificate is OK
        // Otherwise it is a revoked certificate that has been archived and we must return REVOKED
        final int revReason = certificateData.getRevocationReason(); // Read revocationReason from database if we really need to..
        if (revReason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL || revReason == RevokedCertInfo.NOT_REVOKED) {
            return new CertificateStatus(CertificateStatus.OK.toString(), pId);
        }
        return new CertificateStatus(certificateData.getRevocationDate(), revReason, pId);
    }


}
