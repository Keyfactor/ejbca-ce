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

import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for certificates from RA UI.
 */
public class RaCertificateSearchRequestV2 implements Serializable, Comparable<RaCertificateSearchRequestV2> {

    private static final long serialVersionUID = 1L;
    
    // Requests without pagination return the total count only (1 result).
    public static final int DEFAULT_MAX_RESULTS = 25;

    private int maxResults = DEFAULT_MAX_RESULTS;
    private int pageNumber = 0;
    private String orderProperty = "";
    private String orderOperation = "";
    private List<Integer> eepIds = new ArrayList<>();
    private List<Integer> cpIds = new ArrayList<>();
    private List<Integer> caIds = new ArrayList<>();
    private String subjectDnSearchString = "";
    private boolean subjectDnSearchExact = false;
    private String subjectAnSearchString = "";
    private boolean subjectAnSearchExact = false;
    private String usernameSearchString = "";
    private boolean usernameSearchExact = false;
    private String externalAccountIdSearchString = "";
    private boolean externalAccountIdSearchExact = false;
    private String serialNumberSearchStringFromDec = "";
    private String serialNumberSearchStringFromHex = "";
    private long issuedAfter = 0L;
    private long issuedBefore = Long.MAX_VALUE;
    private long expiresAfter = 0L;
    private long expiresBefore = Long.MAX_VALUE;
    private long revokedAfter = 0L;
    private long revokedBefore = Long.MAX_VALUE;
    private long updatedAfter = 0L;
    private long updatedBefore = Long.MAX_VALUE;
    private List<Integer> statuses = new ArrayList<>();
    private List<Integer> revocationReasons = new ArrayList<>();

    /** Default constructor */
    public RaCertificateSearchRequestV2() {}

    /** Copy constructor */
    public RaCertificateSearchRequestV2(final RaCertificateSearchRequestV2 request) {
        maxResults = request.maxResults;
        pageNumber = request.pageNumber;
        orderProperty = request.orderProperty;
        orderOperation = request.orderOperation;
        eepIds.addAll(request.eepIds);
        cpIds.addAll(request.cpIds);
        caIds.addAll(request.caIds);
        subjectDnSearchString = request.subjectDnSearchString;
        subjectDnSearchExact = request.subjectDnSearchExact;
        subjectAnSearchString = request.subjectAnSearchString;
        subjectAnSearchExact = request.subjectAnSearchExact;
        usernameSearchString = request.usernameSearchString;
        usernameSearchExact = request.usernameSearchExact;
        externalAccountIdSearchString = request.externalAccountIdSearchString;
        externalAccountIdSearchExact = request.externalAccountIdSearchExact;
        serialNumberSearchStringFromDec = request.serialNumberSearchStringFromDec;
        serialNumberSearchStringFromHex = request.serialNumberSearchStringFromHex;
        issuedAfter = request.issuedAfter;
        issuedBefore = request.issuedBefore;
        expiresAfter = request.expiresAfter;
        expiresBefore = request.expiresBefore;
        revokedAfter = request.revokedAfter;
        revokedBefore = request.revokedBefore;
        updatedAfter = request.updatedAfter;
        updatedBefore = request.updatedBefore;
        statuses.addAll(request.statuses);
        revocationReasons.addAll(request.revocationReasons);
    }
    
    /** Copy constructor to Bridge V1 and V2 request. Invoked by V1. */
    public RaCertificateSearchRequestV2(final RaCertificateSearchRequest request) {
        maxResults = request.getMaxResults();
        pageNumber = request.getPageNumber();
        eepIds.addAll(request.getEepIds());
        cpIds.addAll(request.getCpIds());
        caIds.addAll(request.getCaIds());
        subjectDnSearchString = request.getSubjectDnSearchString();
        subjectDnSearchExact = request.isSubjectDnSearchExact();
        subjectAnSearchString = request.getSubjectAnSearchString();
        subjectAnSearchExact = request.isSubjectAnSearchExact();
        usernameSearchString = request.getUsernameSearchString();
        usernameSearchExact = request.isUsernameSearchExact();
        externalAccountIdSearchString = request.getExternalAccountIdSearchString();
        externalAccountIdSearchExact = request.isExternalAccountIdSearchExact();
        serialNumberSearchStringFromDec = request.getSerialNumberSearchStringFromDec();
        serialNumberSearchStringFromHex = request.getSerialNumberSearchStringFromHex();
        issuedAfter = request.getIssuedAfter();
        issuedBefore = request.getIssuedBefore();
        expiresAfter = request.getExpiresAfter();
        expiresBefore = request.getExpiresBefore();
        revokedAfter = request.getRevokedAfter();
        revokedBefore = request.getRevokedBefore();
        updatedAfter = request.getUpdatedAfter();
        updatedBefore = request.getUpdatedBefore();
        statuses.addAll(request.getStatuses());
        revocationReasons.addAll(request.getRevocationReasons());
    }

    public int getMaxResults() { 
        return maxResults;
    }
    
    public void setMaxResults(final int maxResults) {
        this.maxResults = maxResults;
    }
    
    public int getPageNumber() {
        return pageNumber;
    }

    public void setPageNumber(final int pageNumber) {
        this.pageNumber = pageNumber;
    }
    
    public void resetMaxResults() {
        this.maxResults = DEFAULT_MAX_RESULTS;
    }
    
    public String getOrderProperty() {
        return orderProperty;
    }

    public void setOrderProperty(final String orderProperty) {
        this.orderProperty = orderProperty;
    }

    public String getOrderOperation() {
        return orderOperation;
    }

    public void setOrderOperation(String orderOperation) {
        this.orderOperation = orderOperation;
    }

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
    public String getExternalAccountIdSearchString() { return externalAccountIdSearchString; }
    public void setExternalAccountIdSearchString(String externalAccountIdSearchString) { this.externalAccountIdSearchString = externalAccountIdSearchString; }
    public boolean isExternalAccountIdSearchExact() { return externalAccountIdSearchExact; }
    public void setExternalAccountIdSearchExact(boolean externalAccountIdSearchExact) { this.externalAccountIdSearchExact = externalAccountIdSearchExact; }
    public String getSerialNumberSearchStringFromDec() { return serialNumberSearchStringFromDec; }
    /** Set the serialNumber search string as a decimal String if it has potential to be a decimal certificate serial number. */
    public void setSerialNumberSearchStringFromDec(final String serialNumberSearchStringFromDec) {
        // Assuming 4 octets and some leading zeroes
        String value = "";
        if (serialNumberSearchStringFromDec.length()>=10) {
            try {
                value = new BigInteger(serialNumberSearchStringFromDec, 10).toString(10);
            } catch (NumberFormatException ignored) {
            }
        }
        this.serialNumberSearchStringFromDec = value;

    }
    public String getSerialNumberSearchStringFromHex() { return serialNumberSearchStringFromHex; }
    /** Set the serialNumber search string as a decimal String if it has potential to be a hex certificate serial number. */
    public void setSerialNumberSearchStringFromHex(final String serialNumberSearchStringFromHex) {
        // Assuming 4 octets and some leading zeroes
        String value = "";
        if (serialNumberSearchStringFromHex.length()>=8) {
            try {
                value = new BigInteger(serialNumberSearchStringFromHex, 16).toString(10);
            } catch (NumberFormatException ignored) {
            }
        }
        this.serialNumberSearchStringFromHex = value;
    }
    public long getIssuedAfter() { return issuedAfter; }
    public void setIssuedAfter(final long issuedAfter) { this.issuedAfter = issuedAfter; }
    public boolean isIssuedAfterUsed() { return issuedAfter>0L; }
    public void resetIssuedAfter() { this.issuedAfter = 0L; }

    public long getIssuedBefore() { return issuedBefore; }
    public void setIssuedBefore(final long issuedBefore) { this.issuedBefore = issuedBefore; }
    public boolean isIssuedBeforeUsed() { return issuedBefore<Long.MAX_VALUE; }
    public void resetIssuedBefore() { this.issuedBefore = Long.MAX_VALUE; }

    public long getExpiresAfter() { return expiresAfter; }
    public void setExpiresAfter(final long expiresAfter) { this.expiresAfter = expiresAfter; }
    public boolean isExpiresAfterUsed() { return expiresAfter>0L; }
    public void resetExpiresAfter() { this.expiresAfter = 0L; }

    public long getExpiresBefore() { return expiresBefore; }
    public void setExpiresBefore(final long expiresBefore) { this.expiresBefore = expiresBefore; }
    public boolean isExpiresBeforeUsed() { return expiresBefore<Long.MAX_VALUE; }
    public void resetExpiresBefore() { this.expiresBefore = Long.MAX_VALUE; }

    public long getRevokedAfter() { return revokedAfter; }
    public void setRevokedAfter(final long revokedAfter) { this.revokedAfter = revokedAfter; }
    public boolean isRevokedAfterUsed() { return revokedAfter>0L; }
    public void resetRevokedAfter() { this.revokedAfter = 0L; }

    public long getRevokedBefore() { return revokedBefore; }
    public void setRevokedBefore(final long revokedBefore) { this.revokedBefore = revokedBefore; }
    public boolean isRevokedBeforeUsed() { return revokedBefore<Long.MAX_VALUE; }
    public void resetRevokedBefore() { this.revokedBefore = Long.MAX_VALUE; }

    public long getUpdatedAfter() { return updatedAfter; }
    public void setUpdatedAfter(final long updatedAfter) { this.updatedAfter = updatedAfter; }
    public boolean isUpdatedAfterUsed() { return updatedAfter>0L; }
    public void resetUpdatedAfter() { this.updatedAfter = 0L; }

    public long getUpdatedBefore() { return updatedBefore; }
    public void setUpdatedBefore(final long updatedBefore) { this.updatedBefore = updatedBefore; }
    public boolean isUpdatedBeforeUsed() { return updatedBefore<Long.MAX_VALUE; }
    public void resetUpdatedBefore() { this.updatedBefore = Long.MAX_VALUE; }

    public List<Integer> getStatuses() { return statuses; }
    public void setStatuses(final List<Integer> statuses) { this.statuses = statuses; }
    public List<Integer> getRevocationReasons() { return revocationReasons; }
    public void setRevocationReasons(final List<Integer> revocationReasons) { this.revocationReasons = revocationReasons; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public boolean equals(final Object object) {
        if (!(object instanceof RaCertificateSearchRequestV2)) {
            return false;
        }
        final RaCertificateSearchRequestV2 request = (RaCertificateSearchRequestV2) object;
        return compareTo(request) == 0 && request.getPageNumber() == this.pageNumber;
    }

    // negative = this object is less (more narrow) than other. E.g. only when other contains this and more.
    // positive = this object is greater (wider) than other
    // zero = this object is equal to other
    @Override
    public int compareTo(final RaCertificateSearchRequestV2 other) {
        if (other==null) {
            return 1;
        }
        // First check if there is any there is any indication that this does not contain the whole other
        if (maxResults>other.maxResults || pageNumber>other.pageNumber ||
                isWider(eepIds, other.eepIds) || isWider(cpIds, other.cpIds) || isWider(caIds, other.caIds) ||
                issuedAfter<other.issuedAfter || issuedBefore>other.issuedBefore ||
                expiresAfter<other.expiresAfter || expiresBefore>other.expiresBefore ||
                revokedAfter<other.revokedAfter || revokedBefore>other.revokedBefore ||
                updatedAfter<other.updatedAfter || updatedBefore>other.updatedBefore ||
                isWider(subjectDnSearchString, other.subjectDnSearchString) ||
                isWider(subjectDnSearchExact, other.subjectDnSearchExact) ||
                isWider(subjectAnSearchString, other.subjectAnSearchString) ||
                isWider(subjectAnSearchExact, other.subjectAnSearchExact) ||
                isWider(usernameSearchString, other.usernameSearchString) ||
                isWider(usernameSearchExact, other.usernameSearchExact) ||
                isWider(externalAccountIdSearchString, other.externalAccountIdSearchString) ||
                isWider(externalAccountIdSearchExact, other.externalAccountIdSearchExact) ||
                isWider(serialNumberSearchStringFromDec, other.serialNumberSearchStringFromDec) ||
                isWider(serialNumberSearchStringFromHex, other.serialNumberSearchStringFromHex) ||
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
                updatedAfter>other.updatedAfter || updatedBefore<other.updatedBefore ||
                isMoreNarrow(subjectDnSearchString, other.subjectDnSearchString) ||
                isMoreNarrow(subjectDnSearchExact, other.subjectDnSearchExact) ||
                isMoreNarrow(subjectAnSearchString, other.subjectAnSearchString) ||
                isMoreNarrow(subjectAnSearchExact, other.subjectAnSearchExact) ||
                isMoreNarrow(usernameSearchString, other.usernameSearchString) ||
                isMoreNarrow(usernameSearchExact, other.usernameSearchExact) ||
                isMoreNarrow(externalAccountIdSearchString, other.externalAccountIdSearchString) ||
                isMoreNarrow(externalAccountIdSearchExact, other.externalAccountIdSearchExact) ||
                isMoreNarrow(serialNumberSearchStringFromDec, other.serialNumberSearchStringFromDec) ||
                isMoreNarrow(serialNumberSearchStringFromHex, other.serialNumberSearchStringFromHex) ||
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
    public boolean matchIssuedInterval(final Long notBefore) {
        if (isIssuedAfterUsed() && (notBefore==null || notBefore.longValue()<issuedAfter)) {
            return false;
        }
        if (isIssuedBeforeUsed() && (notBefore==null || notBefore.longValue()>issuedBefore)) {
            return false;
        }
        return true;
    }

    /** @return true if the expireDate is matched by this search. */
    public boolean matchExpiresInterval(final long expireDate) {
        if (isExpiresAfterUsed() && expireDate<expiresAfter) {
            return false;
        }
        if (isExpiresBeforeUsed() && expireDate>expiresBefore) {
            return false;
        }
        return true;
    }

    /** @return true if the revocationDate is matched by this search. */
    public boolean matchRevokedInterval(long revocationDate) {
        if (isRevokedAfterUsed() && revocationDate<revokedAfter) {
            return false;
        }
        if (isRevokedBeforeUsed() && revocationDate>revokedBefore) {
            return false;
        }
        return true;
    }

    /** @return true if the updateTime is matched by this search. */
    public boolean matchUpdateTimeInterval(final long updateTime) {
        if (isUpdatedAfterUsed() && updateTime<updatedAfter) {
            return false;
        }
        if (isUpdatedBeforeUsed() && updateTime>updatedBefore) {
            return false;
        }
        return true;
    }

    /** @return true if the serialNumber is matched by this search (either as decimal or hexadecimal). */
    public boolean matchSerialNumber(final String serialNumber) {
        return serialNumber.equals(getSerialNumberSearchStringFromDec()) || serialNumber.equals(getSerialNumberSearchStringFromHex());
    }
    
    /** @return true if the username is matched by this search. */
    public boolean matchUsername(final String username) {
        return username != null && ((!usernameSearchExact && username.toUpperCase().contains(usernameSearchString.toUpperCase())) ||
                                    (usernameSearchExact && username.equalsIgnoreCase(usernameSearchString)));
    }

    /** @return true if the external account id is matched by this search. */
    public boolean matchExternalAccountId(final String externalAccountId) {
        return externalAccountId != null && (externalAccountIdSearchExact ?
                externalAccountId.equalsIgnoreCase(usernameSearchString) :
                externalAccountId.toUpperCase().contains(usernameSearchString.toUpperCase()));
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

    /** @return true if the certificate status and revocation reason is matched by this search. */
    public boolean matchStatusAndReason(final int status, final int revocationReason) {
        if (!statuses.isEmpty() && !statuses.contains(status)) {
            return false;
        }
        if (!revocationReasons.isEmpty() && !revocationReasons.contains(revocationReason)) {
            return false;
        }
        return true;
    }
}
