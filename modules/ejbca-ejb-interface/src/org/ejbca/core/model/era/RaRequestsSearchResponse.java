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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Response of approval listing from RA GUI.
 * 
 * @version $Id$
 */
public class RaRequestsSearchResponse implements Serializable {

    // TODO: Make Externalizable instead to handle for future versioning. And consider creating a common base class for this one and RaCertificateSearchResponse
    
    private static final long serialVersionUID = 1L;

    private List<RaApprovalRequestInfo> approvalRequests = new ArrayList<>();
    private boolean mightHaveMoreResults = false;

    public List<RaApprovalRequestInfo> getApprovalRequests() { return approvalRequests; }
    public void getApprovalRequests(final List<RaApprovalRequestInfo> approvalRequests) { this.approvalRequests = approvalRequests; }

    public boolean isMightHaveMoreResults() { return mightHaveMoreResults; }
    public void setMightHaveMoreResults(boolean mightHaveMoreResults) { this.mightHaveMoreResults = mightHaveMoreResults; }
    
    public void merge(final RaRequestsSearchResponse other) {
        final Map<Integer,RaApprovalRequestInfo> cdwMap = new HashMap<>();
        for (final RaApprovalRequestInfo approvalRequest : approvalRequests) {
            cdwMap.put(approvalRequest.getId(), approvalRequest);
        }
        for (final RaApprovalRequestInfo approvalRequest : other.approvalRequests) {
            cdwMap.put(approvalRequest.getId(), approvalRequest);
        }
        this.approvalRequests.clear();
        this.approvalRequests.addAll(cdwMap.values());
        if (other.isMightHaveMoreResults()) {
            setMightHaveMoreResults(true);
        }
    }
    
}
