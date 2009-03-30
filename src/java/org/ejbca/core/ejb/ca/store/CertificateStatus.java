/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.store;

import java.util.Date;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;

// this should be an enum declaration. but the stupid ejbdoclet don't understand enums
public class CertificateStatus {
    public final static CertificateStatus REVOKED=new CertificateStatus("REVOKED");
    public final static CertificateStatus NOT_AVAILABLE=new CertificateStatus("NOT_AVAILABLE");
    public final static CertificateStatus OK = new CertificateStatus("OK");
    public final static CertificateStatus getIt( CertificateDataLocal data) {
        if ( data==null )
            return NOT_AVAILABLE;
        if ( data.getStatus() != CertificateDataBean.CERT_REVOKED )
            return OK;
        return new CertificateStatus(data.getRevocationDate(), data.getRevocationReason());
    }
    private final String name;
    public final Date revocationDate;
    public final int revocationReason;
    private CertificateStatus(String s) {
        this.name = s;
        this.revocationDate = null;
        this.revocationReason = RevokedCertInfo.NOT_REVOKED;
    }
    private CertificateStatus( long date, int reason ) {
        this.name = CertificateStatus.REVOKED.toString();
        this.revocationDate = new Date(date);
        this.revocationReason = reason;
    }
    public String toString() {
        return this.name;
    }
    public boolean equals(Object obj) {
        return obj instanceof CertificateStatus && this.name.equals(obj.toString());
    }
}
