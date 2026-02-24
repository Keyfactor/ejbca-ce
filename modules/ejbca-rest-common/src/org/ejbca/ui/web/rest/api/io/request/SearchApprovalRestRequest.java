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
package org.ejbca.ui.web.rest.api.io.request;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.swagger.v3.oas.annotations.media.Schema;
import org.ejbca.ui.web.rest.api.validator.ValidSearchApprovalRestRequest;
import java.util.Date;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@ValidSearchApprovalRestRequest
public class SearchApprovalRestRequest {

    @Schema(description = "Search for waiting approvals for this admin", example = "true", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean searchingWaitingForMe;

    @Schema(description = "Search for pending approvals for this admin", example = "true", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean searchingPending;

    @Schema(description = "Search for historical approvals for this admin", example = "true", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean searchingHistorical; // processed

    @Schema(description = "Search the expired approvals", example = "true", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean searchingExpired;

    @Schema(description = "Start date of the approvals to search", example = "2017-01-01", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Date startDate;

    @Schema(description = "End date of the approvals to search", example = "2017-01-01", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Date endDate;

    @Schema(description = "Number of days remaining before approval request expires ", example = "100", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private Date expiresBefore;

    @Schema(description = "Should other admins be included in the search", example = "false", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private boolean includeOtherAdmins;

    @Schema(description = "Custom Subject Distinguished Name for search", example = "CN=John Doe,SURNAME=Doe,GIVENNAME=John,C=SE", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String subjectDn;

    @Schema(description = "Custom Email for search", example = "john@doe.com", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String email;

    public SearchApprovalRestRequest() {
    }

    public boolean isSearchingWaitingForMe() {
        return searchingWaitingForMe;
    }

    public void setSearchingWaitingForMe(final boolean searchingWaitingForMe) {
        this.searchingWaitingForMe = searchingWaitingForMe;
    }

    public boolean isSearchingPending() {
        return searchingPending;
    }

    public void setSearchingPending(final boolean searchingPending) {
        this.searchingPending = searchingPending;
    }

    public boolean isSearchingHistorical() {
        return searchingHistorical;
    }

    public void setSearchingHistorical(final boolean searchingHistorical) {
        this.searchingHistorical = searchingHistorical;
    }

    public boolean isSearchingExpired() {
        return searchingExpired;
    }

    public void setSearchingExpired(final boolean searchingExpired) {
        this.searchingExpired = searchingExpired;
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(final Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(final Date endDate) {
        this.endDate = endDate;
    }

    public Date getExpiresBefore() {
        return expiresBefore;
    }

    public void setExpiresBefore(final Date expiresBefore) {
        this.expiresBefore = expiresBefore;
    }

    public boolean isIncludeOtherAdmins() {
        return includeOtherAdmins;
    }

    public void setIncludeOtherAdmins(final boolean includeOtherAdmins) {
        this.includeOtherAdmins = includeOtherAdmins;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public void setSubjectDn(final String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(final String email) {
        this.email = email;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final SearchApprovalRestRequest request;

        public Builder() {
            request = new SearchApprovalRestRequest();
        }

        public Builder searchingWaitingForMe(boolean searchingWaitingForMe) {
            request.setSearchingWaitingForMe(searchingWaitingForMe);
            return this;
        }

        public Builder searchingPending(boolean searchingPending) {
            request.setSearchingPending(searchingPending);
            return this;
        }

        public Builder searchingHistorical(boolean searchingHistorical) {
            request.setSearchingHistorical(searchingHistorical);
            return this;
        }

        public Builder searchingExpired(boolean searchingExpired) {
            request.setSearchingExpired(searchingExpired);
            return this;
        }

        public Builder startDate(Date startDate) {
            request.setStartDate(startDate);
            return this;
        }

        public Builder endDate(Date endDate) {
            request.setEndDate(endDate);
            return this;
        }

        public Builder expiresBefore(Date expiresBefore) {
            request.setExpiresBefore(expiresBefore);
            return this;
        }

        public Builder includeOtherAdmins(boolean includeOtherAdmins) {
            request.setIncludeOtherAdmins(includeOtherAdmins);
            return this;
        }

        public Builder subjectDn(String subjectDn) {
            request.setSubjectDn(subjectDn);
            return this;
        }

        public Builder email(String email) {
            request.setEmail(email);
            return this;
        }

        public SearchApprovalRestRequest build() {
            return request;
        }
    }
}
