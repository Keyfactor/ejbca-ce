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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class SearchApprovalRestResponse {

    private List<Approval> approvals = new ArrayList<>();

    public List<Approval> getApprovals() {
        return approvals;
    }

    public void setApprovals(final List<Approval> approvals) {
        this.approvals = approvals;
    }

    public SearchApprovalRestResponse() {}

    public static class Approval {

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

        @Schema(description = "Approval status to search", example = "APPROVED", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
        private String status;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public Approval() {}

        public Integer getRequestId() {
            return requestId;
        }

        public void setRequestId(final Integer requestId) {
            this.requestId = requestId;
        }

        public Date getRequestDate() {
            return requestDate;
        }

        public void setRequestDate(final Date requestDate) {
            this.requestDate = requestDate;
        }

        public Date getExpirationDate() {
            return expirationDate;
        }

        public void setExpirationDate(final Date expirationDate) {
            this.expirationDate = expirationDate;
        }

        public String getRequestType() {
            return requestType;
        }

        public void setRequestType(final String requestType) {
            this.requestType = requestType;
        }

        public String getRequestedBy() {
            return requestedBy;
        }

        public void setRequestedBy(final String requestedBy) {
            this.requestedBy = requestedBy;
        }

        public boolean isCanBeApprovedByMe() {
            return canBeApprovedByMe;
        }

        public void setCanBeApprovedByMe(final boolean canBeApprovedByMe) {
            this.canBeApprovedByMe = canBeApprovedByMe;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private final Approval response;

            private Builder() {
                response = new Approval();
            }

            public Builder requestId(final Integer requestId) {
                response.requestId = requestId;
                return this;
            }

            public Builder requestDate(final Date requestDate) {
                response.requestDate = requestDate;
                return this;
            }

            public Builder expirationDate(final Date expirationDate) {
                response.expirationDate = expirationDate;
                return this;
            }

            public Builder requestType(final String requestType) {
                response.requestType = requestType;
                return this;
            }

            public Builder requestedBy(final String requestedBy) {
                response.requestedBy = requestedBy;
                return this;
            }

            public Builder canBeApprovedByMe(final boolean canBeApprovedByMe) {
                response.canBeApprovedByMe = canBeApprovedByMe;
                return this;
            }

            public Builder approvalStatus(final String approvalStatus) {
                response.status = approvalStatus;
                return this;
            }

            public Approval build() {
                return response;
            }
        }
    }
}