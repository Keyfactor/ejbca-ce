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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Search request for certificates from RA UI.
 * 
 * @version $Id$
 */
public class RaCertificateSearchRequest implements Serializable, Comparable<RaCertificateSearchRequest> {

    // TODO: Make Externalizable instead to handle for future versioning

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(RaCertificateSearchRequest.class);
    public static int DEFAULT_MAX_RESULTS = 25;

    private int maxResults = DEFAULT_MAX_RESULTS;
    private List<Integer> eepIds = new ArrayList<>();
    private List<Integer> cpIds = new ArrayList<>();
    private List<Integer> caIds = new ArrayList<>();
    private String genericSearchString = "";
    private long issuedAfter = 0L;
    private long issuedBefore = Long.MAX_VALUE;
    private long expiresAfter = 0L;
    private long expiresBefore = Long.MAX_VALUE;
    private long revokedAfter = 0L;
    private long revokedBefore = Long.MAX_VALUE;
    private List<Integer> statuses = new ArrayList<>();
    private List<Integer> revocationReasons = new ArrayList<>();

    /** Default constructor */
    public RaCertificateSearchRequest() {}
    
    /** Copy constructor */
    public RaCertificateSearchRequest(final RaCertificateSearchRequest request) {
        maxResults = request.maxResults;
        eepIds.addAll(request.eepIds);
        cpIds.addAll(request.cpIds);
        caIds.addAll(request.caIds);
        genericSearchString = request.genericSearchString;
        issuedAfter = request.issuedAfter;
        issuedBefore = request.issuedBefore;
        expiresAfter = request.expiresAfter;
        expiresBefore = request.expiresBefore;
        revokedAfter = request.revokedAfter;
        revokedBefore = request.revokedBefore;
        statuses.addAll(request.statuses);
        revocationReasons.addAll(request.revocationReasons);
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
    public long getIssuedAfter() { return issuedAfter; }
    public void setIssuedAfter(final long issuedAfter) { this.issuedAfter = issuedAfter; }
    public long getIssuedBefore() { return issuedBefore; }
    public void setIssuedBefore(final long issuedBefore) { this.issuedBefore = issuedBefore; }
    public long getExpiresAfter() { return expiresAfter; }
    public void setExpiresAfter(final long expiresAfter) { this.expiresAfter = expiresAfter; }
    public long getExpiresBefore() { return expiresBefore; }
    public void setExpiresBefore(final long expiresBefore) { this.expiresBefore = expiresBefore; }
    public long getRevokedAfter() { return revokedAfter; }
    public void setRevokedAfter(final long revokedAfter) { this.revokedAfter = revokedAfter; }
    public long getRevokedBefore() { return revokedBefore; }
    public void setRevokedBefore(final long revokedBefore) { this.revokedBefore = revokedBefore; }
    public List<Integer> getStatuses() { return statuses; }
    public void setStatuses(final List<Integer> statuses) { this.statuses = statuses; }
    public List<Integer> getRevocationReasons() { return revocationReasons; }
    public void setRevocationReasons(final List<Integer> revocationReasons) { this.revocationReasons = revocationReasons; }

    /** @return the generic search string as a decimal String if it has potential to be a decimal certificate serial number. */
    public String getGenericSearchStringAsDecimal() {
        // Assuming 8 octets and some leading zeroes
        if (genericSearchString.length()>=16) {
            try {
                return new BigInteger(genericSearchString, 10).toString(10);
            } catch (NumberFormatException e) {
            }
        }
        return null;
    }
    /** @return the generic search string as a decimal String if it has potential to be a hex certificate serial number. */
    public String getGenericSearchStringAsHex() {
        // Assuming 8 octets and maybe a leading zero
        if (genericSearchString.length()>=14) {
            try {
                return new BigInteger(genericSearchString, 16).toString(10);
            } catch (NumberFormatException e) {
            }
        }
        return null;
    }
    
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
        // First check if there is any there is any indication that this does not contain the whole other
        if (maxResults>other.maxResults ||
                isWider(eepIds, other.eepIds) || isWider(cpIds, other.cpIds) || isWider(caIds, other.caIds) ||
                issuedAfter<other.issuedAfter || issuedBefore>other.issuedBefore ||
                expiresAfter<other.expiresAfter || expiresBefore>other.expiresBefore ||
                revokedAfter<other.revokedAfter || revokedBefore>other.revokedBefore ||
                (getGenericSearchStringAsDecimal()!=null && !getGenericSearchStringAsDecimal().equals(other.getGenericSearchStringAsDecimal())) ||
                (getGenericSearchStringAsHex()!=null && !getGenericSearchStringAsHex().equals(other.getGenericSearchStringAsHex())) ||
                !genericSearchString.contains(other.genericSearchString) ||
                isWider(statuses, other.statuses) || isWider(revocationReasons, other.revocationReasons)) {
            // This does not contain whole other → wider
            return 1;
        }
        // Next check if this object is more narrow than the other
        if (maxResults<other.maxResults ||
                isMoreNarrow(eepIds, other.eepIds) || isMoreNarrow(cpIds, other.cpIds) || isMoreNarrow(caIds, other.caIds) ||
                issuedAfter>other.issuedAfter || issuedBefore<other.issuedBefore ||
                expiresAfter>other.expiresAfter || expiresBefore<other.expiresBefore ||
                revokedAfter>other.revokedAfter || revokedBefore<other.revokedBefore ||
                (genericSearchString.contains(other.genericSearchString) && !other.genericSearchString.contains(genericSearchString)) ||
                isMoreNarrow(statuses, other.statuses) || isMoreNarrow(revocationReasons, other.revocationReasons)) {
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
