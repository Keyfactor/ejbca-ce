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

public class RaEndEntitySearchRequestV2 extends RaEndEntitySearchRequest {

    private static final long serialVersionUID = 566655588728904203L;
    private String sortOperation;
    
    private RaEndEntitySearchPaginationSummary searchSummary;
    private String additionalConstraint;

    public String getSortOperation() {
        return sortOperation;
    }

    public void setSortOperation(String sortingOperation) {
        this.sortOperation = sortingOperation;
    }    

    @Override
    public String toString() {
        return "RaEndEntitySearchRequestV2 [sortOperation=" + sortOperation + ", getEepIds()=" + getEepIds() + ", getCpIds()=" + getCpIds()
                + ", getCaIds()=" + getCaIds() + ", getSubjectDnSearchString()=" + getSubjectDnSearchString() + ", isSubjectDnSearchExact()="
                + isSubjectDnSearchExact() + ", getSubjectAnSearchString()=" + getSubjectAnSearchString() + ", isSubjectAnSearchExact()="
                + isSubjectAnSearchExact() + ", getUsernameSearchString()=" + getUsernameSearchString() + ", isUsernameSearchExact()="
                + isUsernameSearchExact() + ", getModifiedAfter()=" + getModifiedAfter() + ", isModifiedAfterUsed()=" + isModifiedAfterUsed()
                + ", getModifiedBefore()=" + getModifiedBefore() + ", isModifiedBeforeUsed()=" + isModifiedBeforeUsed() + ", getStatuses()="
                + getStatuses() + "]";
    }

    public RaEndEntitySearchPaginationSummary getSearchSummary() {
        return searchSummary;
    }

    public void setSearchSummary(RaEndEntitySearchPaginationSummary searchSummary) {
        this.searchSummary = searchSummary;
    }

    public String getAdditionalConstraint() {
        return additionalConstraint;
    }

    public void setAdditionalConstraint(String additionalConstarint) {
        this.additionalConstraint = additionalConstarint;
    }

    public void incrementPageNumber() {
        this.setPageNumber(getPageNumber() + 1);
    }
    
    
}
