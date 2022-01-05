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
package org.cesecore.certificates.ca;

import java.util.ArrayList;
import java.util.HashMap;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

public class CitsCaInfo extends CAInfo {
    
    private static final long serialVersionUID = -2024462945820076720L;
    
    private String certificateId;
    
    public CitsCaInfo() {
        setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
        setStatus(CAConstants.CA_WAITING_CERTIFICATE_RESPONSE);
        setAcceptRevocationNonExistingEntry(true);
        setCertificateChain(null);
        setCAType(CATYPE_CITS);
        setApprovals(new HashMap<>());
        setExtendedCAServiceInfos(new ArrayList<ExtendedCAServiceInfo>());
    }

    @Override
    public boolean isExpirationInclusive() {
        return false;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.subjectdn = CITS_SUBJECTDN_PREFIX + certificateId;
        this.caid = this.subjectdn.hashCode();
        this.certificateId = certificateId;
    }
    
    
}
