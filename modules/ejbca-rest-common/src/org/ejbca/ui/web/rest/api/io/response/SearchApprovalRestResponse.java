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
package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Date;

public class SearchApprovalRestResponse {

    @Schema(description = "Approval request id", example = "12345")
    private Integer requestId;

    @Schema(description = "Approval request date", example = "2026-02-06 21:50:31+01:00")
    private Date requestDate;

    @Schema(description = "Approval expiration date", example = "2026-02-06 21:50:31+01:00")
    private Date expirationDate;

    @Schema(description = "Approval request type", example = "Add End Entity")
    private String requestType;

    @Schema(description = "Approval request initiator admin", example = "SuperAdmin")
    private String requestedBy;

    @Schema(description = "Can this approval request be approved by current admin?", example = "true")
    private boolean canBeApprovedByMe;

    private SearchApprovalRestResponse() {}

    public Integer getRequestId() {
        return requestId;
    }

    public void setRequestId(Integer requestId) {
        this.requestId = requestId;
    }

    public Date getRequestDate() {
        return requestDate;
    }

    public void setRequestDate(Date requestDate) {
        this.requestDate = requestDate;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getRequestType() {
        return requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public void setRequestedBy(String requestedBy) {
        this.requestedBy = requestedBy;
    }

    public boolean isCanBeApprovedByMe() {
        return canBeApprovedByMe;
    }

    public void setCanBeApprovedByMe(boolean canBeApprovedByMe) {
        this.canBeApprovedByMe = canBeApprovedByMe;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final SearchApprovalRestResponse response;

        private Builder() {
            response = new SearchApprovalRestResponse();
        }

        public Builder requestId(Integer requestId) {
            response.requestId = requestId;
            return this;
        }

        public Builder requestDate(Date requestDate) {
            response.requestDate = requestDate;
            return this;
        }

        public Builder expirationDate(Date expirationDate) {
            response.expirationDate = expirationDate;
            return this;
        }

        public Builder requestType(String requestType) {
            response.requestType = requestType;
            return this;
        }

        public Builder requestedBy(String requestedBy) {
            response.requestedBy = requestedBy;
            return this;
        }

        public Builder canBeApprovedByMe(boolean canBeApprovedByMe) {
            response.canBeApprovedByMe = canBeApprovedByMe;
            return this;
        }

        public SearchApprovalRestResponse build() {
            return response;
        }
    }

}
