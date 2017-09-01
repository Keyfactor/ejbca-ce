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

import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for end entities from RA UI.
 * 
 * @version $Id$
 */
public class RaEndEntitySearchRequest implements Serializable, Comparable<RaEndEntitySearchRequest> {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(RaEndEntitySearchRequest.class);
    public static int DEFAULT_MAX_RESULTS = 25;

    private int maxResults = DEFAULT_MAX_RESULTS;
    private List<Integer> eepIds = new ArrayList<>();
    private List<Integer> cpIds = new ArrayList<>();
    private List<Integer> caIds = new ArrayList<>();
    private String subjectDnSearchString = "";
    private boolean subjectDnSearchExact = false;
    private String subjectAnSearchString = "";
    private boolean subjectAnSearchExact = false;
    private String usernameSearchString = "";
    private boolean usernameSearchExact = false;
    private long modifiedAfter = 0L;
    private long modifiedBefore = Long.MAX_VALUE;
    private List<Integer> statuses = new ArrayList<>();

    /** Default constructor */
    public RaEndEntitySearchRequest() {}
    
    /** Copy constructor */
    public RaEndEntitySearchRequest(final RaEndEntitySearchRequest request) {
        maxResults = request.maxResults;
        eepIds.addAll(request.eepIds);
        cpIds.addAll(request.cpIds);
        caIds.addAll(request.caIds);
        subjectDnSearchString = request.subjectDnSearchString;
        subjectDnSearchExact = request.subjectDnSearchExact;
        subjectAnSearchString = request.subjectAnSearchString;
        subjectAnSearchExact = request.subjectAnSearchExact;
        usernameSearchString = request.usernameSearchString;
        usernameSearchExact = request.usernameSearchExact;
        modifiedAfter = request.modifiedAfter;
        modifiedBefore = request.modifiedBefore;
        statuses.addAll(request.statuses);
    }

    public int getMaxResults() { return maxResults; }
    public void setMaxResults(final int maxResults) { this.maxResults = maxResults; }
    public List<Integer> getEepIds() { return eepIds; }
    public void setEepIds(final List<Integer> eepIds) { this.eepIds = eepIds; }
    public List<Integer> getCpIds() { return cpIds; }
    public void setCpIds(final List<Integer> cpIds) { this.cpIds = cpIds; }
    public List<Integer> getCaIds() { return caIds; }
    public void setCaIds(final List<Integer> caIds) { this.caIds = caIds; }
    public String getSubjectDnSearchString() { return subjectDnSearchString; }
    public void setSubjectDnSearchString(final String subjectDnSearchString) { this.subjectDnSearchString = subjectDnSearchString; }
    public boolean isSubjectDnSearchExact() { return subjectDnSearchExact; }
    public void setSubjectDnSearchExact(final boolean subjectDnSearchExact) { this.subjectDnSearchExact = subjectDnSearchExact; }
    public String getSubjectAnSearchString() { return subjectAnSearchString; }
    public void setSubjectAnSearchString(final String subjectAnSearchString) { this.subjectAnSearchString = subjectAnSearchString; }
    public boolean isSubjectAnSearchExact() { return subjectAnSearchExact; }
    public void setSubjectAnSearchExact(final boolean subjectAnSearchExact) { this.subjectAnSearchExact = subjectAnSearchExact; }
    public String getUsernameSearchString() { return usernameSearchString; }
    public void setUsernameSearchString(final String usernameSearchString) { this.usernameSearchString = usernameSearchString; }
    public boolean isUsernameSearchExact() { return usernameSearchExact; }
    public void setUsernameSearchExact(final boolean usernameSearchExact) { this.usernameSearchExact = usernameSearchExact; }

    public long getModifiedAfter() { return modifiedAfter; }
    public void setModifiedAfter(final long modifiedAfter) { this.modifiedAfter = modifiedAfter; }
    public boolean isModifiedAfterUsed() { return modifiedAfter>0L; }
    public void resetModifiedAfter() { this.modifiedAfter = 0L; }

    public long getModifiedBefore() { return modifiedBefore; }
    public void setModifiedBefore(final long modifiedBefore) { this.modifiedBefore = modifiedBefore; }
    public boolean isModifiedBeforeUsed() { return modifiedBefore<Long.MAX_VALUE; }
    public void resetModifiedBefore() { this.modifiedBefore = Long.MAX_VALUE; }

    public List<Integer> getStatuses() { return statuses; }
    public void setStatuses(final List<Integer> statuses) { this.statuses = statuses; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
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
                modifiedAfter<other.modifiedAfter || modifiedBefore>other.modifiedBefore ||
                isWider(subjectDnSearchString, other.subjectDnSearchString) ||
                isWider(subjectDnSearchExact, other.subjectDnSearchExact) ||
                isWider(subjectAnSearchString, other.subjectAnSearchString) ||
                isWider(subjectAnSearchExact, other.subjectAnSearchExact) ||
                isWider(usernameSearchString, other.usernameSearchString) ||
                isWider(usernameSearchExact, other.usernameSearchExact) ||
                isWider(statuses, other.statuses)) {
            // This does not contain whole other → wider
            return 1;
        }
        // Next check if this object is more narrow than the other
        if (maxResults<other.maxResults ||
                isMoreNarrow(eepIds, other.eepIds) || isMoreNarrow(cpIds, other.cpIds) || isMoreNarrow(caIds, other.caIds) ||
                modifiedAfter>other.modifiedAfter || modifiedBefore<other.modifiedBefore ||
                isMoreNarrow(subjectDnSearchString, other.subjectDnSearchString) ||
                isMoreNarrow(subjectDnSearchExact, other.subjectDnSearchExact) ||
                isMoreNarrow(subjectAnSearchString, other.subjectAnSearchString) ||
                isMoreNarrow(subjectAnSearchExact, other.subjectAnSearchExact) ||
                isMoreNarrow(usernameSearchString, other.usernameSearchString) ||
                isMoreNarrow(usernameSearchExact, other.usernameSearchExact) ||
                isMoreNarrow(statuses, other.statuses)) {
            // This does contain whole other, but other does not contain whole this → more narrow
            return -1;
        }
        return 0;
    }
    
    /** @return true if thisObject does contain whole other, but other does not contain whole this → more narrow */
    private boolean isMoreNarrow(final List<Integer> thisObject, final List<Integer> otherObject) {
        return thisObject.containsAll(otherObject) && !otherObject.containsAll(thisObject);
    }
    /** @return true if thisObject does contain whole other, but other does not contain whole this → more narrow */
    private boolean isMoreNarrow(final String thisObject, final String otherObject) {
        return thisObject.contains(otherObject) && !otherObject.contains(thisObject);
    }
    /** @return true if thisObject does contain whole other, but other does not contain whole this → more narrow */
    private boolean isMoreNarrow(final boolean thisObjectExact, final boolean otherObjectExact) {
        return thisObjectExact && !otherObjectExact;
    }
    /** @return true if thisObject does not contain whole other → wider */
    private boolean isWider(final List<Integer> thisObject, final List<Integer> otherObject) {
        return !thisObject.containsAll(otherObject);
    }
    /** @return true if thisObject does not contain whole other → wider */
    private boolean isWider(final String thisObject, final String otherObject) {
        return !thisObject.contains(otherObject);
    }
    /** @return true if thisObject does not contain whole other → wider */
    private boolean isWider(final boolean thisObjectExact, final boolean otherObjectExact) {
        return !thisObjectExact && otherObjectExact;
    }

    /** @return true if the endEntityProfileId is matched by this search. */
    public boolean matchEep(final int endEntityProfileId) { return eepIds.isEmpty() || eepIds.contains(Integer.valueOf(endEntityProfileId)); }
    /** @return true if the certificateId is matched by this search. */
    public boolean matchCp(final int certificateProfileId) { return cpIds.isEmpty() || cpIds.contains(Integer.valueOf(certificateProfileId)); }
    /** @return true if the endEntityProfileId is matched by this search. */
    public boolean matchCa(final int caId) { return caIds.isEmpty() || caIds.contains(Integer.valueOf(caId)); }

    /** @return true if the notBefore is matched by this search. */
    public boolean matchModifiedInterval(final Long modified) {
        if (isModifiedAfterUsed() && (modified==null || modified.longValue()<modifiedAfter)) {
            return false;
        }
        if (isModifiedBeforeUsed() && (modified==null || modified.longValue()>modifiedBefore)) {
            return false;
        }
        return true;
    }

    /** @return true if the username is matched by this search. */
    public boolean matchUsername(final String username) {
        return username != null && ((!usernameSearchExact && username.toUpperCase().contains(usernameSearchString.toUpperCase())) || 
                                    (usernameSearchExact && username.equalsIgnoreCase(usernameSearchString)));
    }
    /** @return true if the subjectDn is matched by this search. */
    public boolean matchSubjectDn(final String subjectDn) {
        return subjectDn != null && ((!subjectDnSearchExact && subjectDn.toUpperCase().contains(subjectDnSearchString.toUpperCase())) || 
                                    (subjectDnSearchExact && subjectDn.equalsIgnoreCase(subjectDnSearchString)));
    }
    /** @return true if the subjectAn is matched by this search. */
    public boolean matchSubjectAn(final String subjectAn) {
        return subjectAn != null && ((!subjectAnSearchExact && subjectAn.contains(subjectAnSearchString)) || (subjectAnSearchExact && subjectAn.equals(subjectAnSearchString)));
    }

    /** @return true if the EE status is matched by this search. */
    public boolean matchStatus(final int status) {
        if (!statuses.isEmpty() && !statuses.contains(status)) {
            return false;
        }
        return true;
    }
}
