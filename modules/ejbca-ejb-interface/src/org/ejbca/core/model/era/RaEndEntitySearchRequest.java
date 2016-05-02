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

/**
 * Search request for end entities from RA UI.
 * 
 * @version $Id$
 */
public class RaEndEntitySearchRequest implements Serializable, Comparable<RaEndEntitySearchRequest> {

    // TODO: Make Externalizable instead to handle for future versioning

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(RaEndEntitySearchRequest.class);
    public static int DEFAULT_MAX_RESULTS = 25;

    private int maxResults = DEFAULT_MAX_RESULTS;
    private List<Integer> eepIds = new ArrayList<>();
    private List<Integer> cpIds = new ArrayList<>();
    private List<Integer> caIds = new ArrayList<>();
    private String genericSearchString = "";
    private long createdAfter = Long.MAX_VALUE;
    private long createdBefore = 0L;
    private long modifiedAfter = Long.MAX_VALUE;
    private long modifiedBefore = 0L;
    private List<Integer> statuses = new ArrayList<>();
    private List<Integer> tokenTypes = new ArrayList<>();

    /** Default constructor */
    public RaEndEntitySearchRequest() {}
    
    /** Copy constructor */
    public RaEndEntitySearchRequest(final RaEndEntitySearchRequest request) {
        maxResults = request.maxResults;
        eepIds.addAll(request.eepIds);
        cpIds.addAll(request.cpIds);
        caIds.addAll(request.caIds);
        genericSearchString = request.genericSearchString;
        createdAfter = request.createdAfter;
        createdBefore = request.createdBefore;
        modifiedAfter = request.modifiedAfter;
        modifiedBefore = request.modifiedBefore;
        statuses.addAll(request.statuses);
        tokenTypes.addAll(request.tokenTypes);
    }

    public int getMaxResults() { return maxResults; }
    public void setMaxResults(final int maxResults) { this.maxResults = maxResults; }
    public List<Integer> getEepIds() { return eepIds; }
    public void setEepIds(final List<Integer> eepIds) { this.eepIds = eepIds; }
    public List<Integer> getCpIds() { return cpIds; }
    public void setCpIds(final List<Integer> cpIds) { this.cpIds = cpIds; }
    public List<Integer> getCaIds() { return caIds; }
    public void setCaIds(final List<Integer> caIds) { this.caIds = caIds; }
    public String getGenericSearchString() { return genericSearchString; }
    public void setGenericSearchString(final String genericSearchString) { this.genericSearchString = genericSearchString; }
    public long getCreatedAfter() { return createdAfter; }
    public void setCreatedAfter(final long createdAfter) { this.createdAfter = createdAfter; }
    public long getCreatedBefore() { return createdBefore; }
    public void setCreatedBefore(final long createdBefore) { this.createdBefore = createdBefore; }
    public long getModifiedAfter() { return modifiedAfter; }
    public void setModifiedAfter(final long modifiedAfter) { this.modifiedAfter = modifiedAfter; }
    public long getModifiedBefore() { return modifiedBefore; }
    public void setModifiedBefore(final long modifiedBefore) { this.modifiedBefore = modifiedBefore; }
    public List<Integer> getStatuses() { return statuses; }
    public void setStatuses(final List<Integer> statuses) { this.statuses = statuses; }
    public List<Integer> getTokenTypes() { return tokenTypes; }
    public void setTokenTypes(final List<Integer> tokenTypes) { this.tokenTypes = tokenTypes; }

    public boolean equals(final Object object) {
        if (!(object instanceof RaEndEntitySearchRequest)) {
            return false;
        }
        return compareTo((RaEndEntitySearchRequest) object)==0;
    }

    // negative = this object is less (more narrow) than other. E.g. only when other contains this and more.
    // positive = this object is greater (wider) than other
    // zero = this object is equal to other
    @Override
    public int compareTo(final RaEndEntitySearchRequest other) {
        if (other==null) {
            return 1;
        }
        // First check if there is any there is any indication that this does not contain the whole other
        if (maxResults>other.maxResults ||
                isWider(eepIds, other.eepIds) || isWider(cpIds, other.cpIds) || isWider(caIds, other.caIds) ||
                createdAfter<other.createdAfter || createdBefore>other.createdBefore ||
                modifiedAfter<other.modifiedAfter || modifiedBefore>other.modifiedBefore ||
                !genericSearchString.contains(other.genericSearchString) ||
                isWider(statuses, other.statuses) || isWider(tokenTypes, other.tokenTypes)) {
            // This does not contain whole other → wider
            return 1;
        }
        // Next check if this object is more narrow than the other
        if (maxResults<other.maxResults ||
                isMoreNarrow(eepIds, other.eepIds) || isMoreNarrow(cpIds, other.cpIds) || isMoreNarrow(caIds, other.caIds) ||
                createdAfter>other.createdAfter || createdBefore<other.createdBefore ||
                modifiedAfter>other.modifiedAfter || modifiedBefore<other.modifiedBefore ||
                (genericSearchString.contains(other.genericSearchString) && !other.genericSearchString.contains(genericSearchString)) ||
                isMoreNarrow(statuses, other.statuses) || isMoreNarrow(tokenTypes, other.tokenTypes)) {
            // This does contain whole other, but other does not contain whole this → more narrow
            return -1;
        }
        return 0;
    }
    
    /** @return true if thisObject does contain whole other, but other does not contain whole this → more narrow */
    private boolean isMoreNarrow(final List<Integer> thisObject, final List<Integer> otherObject) {
        return thisObject.containsAll(otherObject) && !otherObject.containsAll(thisObject);
    }
    /** @return true if thisObject does not contain whole other → wider */
    private boolean isWider(final List<Integer> thisObject, final List<Integer> otherObject) {
        return !thisObject.containsAll(otherObject);
    }
}
