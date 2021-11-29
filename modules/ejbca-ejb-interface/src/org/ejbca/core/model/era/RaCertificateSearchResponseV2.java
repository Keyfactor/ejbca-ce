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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateDataWrapper;

/**
 * Response of certificates search from RA UI V2.
 */
public class RaCertificateSearchResponseV2 implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private List<CertificateDataWrapper> cdws = new ArrayList<>();
    private long totalCount = 0;

    public List<CertificateDataWrapper> getCdws() { return cdws; }
    public void setCdws(List<CertificateDataWrapper> cdws) { this.cdws = cdws; }

    public long getTotalCount() { return totalCount; }
    public void setTotalCount(long count) { totalCount = count; }
    
    public void merge(final RaCertificateSearchResponseV2 other) {
        final LinkedHashMap<String,CertificateDataWrapper> cdwMap = new LinkedHashMap<>();
        for (final CertificateDataWrapper cdw : cdws) {
            cdwMap.put(cdw.getCertificateData().getFingerprint(), cdw);
        }
        for (final CertificateDataWrapper cdw : other.cdws) {
            cdwMap.put(cdw.getCertificateData().getFingerprint(), cdw);
        }
        this.cdws.clear();
        this.cdws.addAll(cdwMap.values());
        setTotalCount(totalCount + other.totalCount);
    }
}
