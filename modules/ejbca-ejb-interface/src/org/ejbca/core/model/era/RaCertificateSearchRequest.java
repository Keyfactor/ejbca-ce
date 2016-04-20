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
import java.util.List;

import org.apache.log4j.Logger;

/**
 * Search request for certificates from RA UI.
 * 
 * @version $Id$
 */
public class RaCertificateSearchRequest implements Serializable, Comparable<RaCertificateSearchRequest> {

    // TODO: Make Externalizable instead to handle for future versioning

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaCertificateSearchRequest.class);

    private int maxResults = 20;
    private List<Integer> caIds = new ArrayList<>();
    private String genericSearchString = "";
    private long expiresAfter = 0;
    private List<Integer> statuses = new ArrayList<>();
    private List<Integer> revocationReasons = new ArrayList<>();

    /** Default constructor */
    public RaCertificateSearchRequest() {}
    
    /** Copy constructor */
    public RaCertificateSearchRequest(final RaCertificateSearchRequest request) {
        maxResults = request.maxResults;
        caIds.addAll(request.caIds);
        genericSearchString = request.genericSearchString;
        expiresAfter = request.expiresAfter;
        statuses.addAll(request.statuses);
        revocationReasons.addAll(request.revocationReasons);
    }

    public int getMaxResults() { return maxResults; }
    public void setMaxResults(int maxResults) { this.maxResults = maxResults; }
    public List<Integer> getCaIds() { return caIds; }
    public void setCaIds(List<Integer> caIds) { this.caIds = caIds; }
    public String getGenericSearchString() { return genericSearchString; }
    public void setGenericSearchString(final String genericSearchString) { this.genericSearchString = genericSearchString; }
    public long getExpiresAfter() { return expiresAfter; }
    public void setExpiresAfter(final long expiresAfter) { this.expiresAfter = expiresAfter; }
    public List<Integer> getStatuses() { return statuses; }
    public void setStatuses(final List<Integer> statuses) { this.statuses = statuses; }
    public List<Integer> getRevocationReasons() { return revocationReasons; }
    public void setRevocationReasons(final List<Integer> revocationReasons) { this.revocationReasons = revocationReasons; }

    public boolean equals(final Object object) {
        if (!(object instanceof RaCertificateSearchRequest)) {
            return false;
        }
        return compareTo((RaCertificateSearchRequest) object)==0;
    }

    // negative = this object is less (more narrow) than other. E.g. only when other contains this and more.
    // positive = this object is greater (wider) than other
    // zero = this object is equal to other
    @Override
    public int compareTo(final RaCertificateSearchRequest other) {
        if (other==null) {
            return 1;
        }
        if (maxResults!=other.maxResults) {
            return maxResults-other.maxResults;
        }
        if (isMoreNarrow(caIds, other.caIds)) { return -1; }
        if (isWider(caIds, other.caIds)) { return 1; }
        //log.info("DEVELOP expiresAfter="+expiresAfter + " other.expiresAfter="+other.expiresAfter);
        if (expiresAfter<other.expiresAfter) {
            return 1;
        }
        if (expiresAfter>other.expiresAfter) {
            return -1;
        }
        if (genericSearchString.contains(other.genericSearchString) && !other.genericSearchString.contains(genericSearchString)) {
            // This does contain whole other, but other does not contain whole this → more narrow
            return -1;
        }
        if (!genericSearchString.contains(other.genericSearchString)) {
            // This does not contain whole other → wider
            return 1;
        }
        if (isMoreNarrow(statuses, other.statuses)) { return -1; }
        if (isWider(statuses, other.statuses)) { return 1; }
        if (isMoreNarrow(revocationReasons, other.revocationReasons)) { return -1; }
        if (isWider(revocationReasons, other.revocationReasons)) { return 1; }
        return 0;
    }
    
    // @return true if thisObject does contain whole other, but other does not contain whole this → more narrow
    private boolean isMoreNarrow(final List<Integer> thisObject, final List<Integer> otherObject) {
        return thisObject.containsAll(otherObject) && !otherObject.containsAll(thisObject);
    }
    // @return true if thisObject does not contain whole other → wider
    private boolean isWider(final List<Integer> thisObject, final List<Integer> otherObject) {
        return !thisObject.containsAll(otherObject);
    }
}
