/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import java.math.BigInteger;
import java.util.Date;

/**
 * Simple data holder for limited certificate entry information extracted from a CRL entry,
 * used for batch persistence of limited CertificateData rows.
 */
public class LimitedCertificateEntry {

    private final BigInteger serialNumber;
    private final Date revocationDate;
    private final Date invalidityDate;
    private final int reasonCode;

    public LimitedCertificateEntry(final BigInteger serialNumber, final Date revocationDate, final Date invalidityDate, final int reasonCode) {
        this.serialNumber = serialNumber;
        this.revocationDate = revocationDate;
        this.invalidityDate = invalidityDate;
        this.reasonCode = reasonCode;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public Date getRevocationDate() {
        return revocationDate != null ? new Date(revocationDate.getTime()) : null;
    }

    public int getReasonCode() {
        return reasonCode;
    }

    public Date getInvalidityDate() {
        return invalidityDate != null ? new Date(invalidityDate.getTime()) : null;
    }
}
