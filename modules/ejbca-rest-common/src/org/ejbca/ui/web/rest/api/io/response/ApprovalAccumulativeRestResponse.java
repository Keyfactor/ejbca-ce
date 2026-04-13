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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "ApprovalAccumulativeRestResponse", description = "Information about accumulative approvals")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApprovalAccumulativeRestResponse {

    @Schema(description = "The action taken on this approval (e.g., APPROVED, REJECTED, PENDING)")
    private String approvalAction;
    @Schema(description = "The date when the approval action was taken", example = "2025-01-01 14:55:00+01:00")
    private String approvalDate;
    @Schema(description = "The admin who performed the approval action", example = "CN=RAAdmin")
    private String approvalAdmin;
    @Schema(description = "Comment provided with the approval action", example = "Approved after verification")
    private String approvalComment;
    @Schema(description = "Number of remaining approvals required", example = "2")
    private Integer remainingApprovals;
    @Schema(description = "If the current user is authorized to perform this approval")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Boolean canApprove;

    public ApprovalAccumulativeRestResponse() {
    }

    public String getApprovalAction() {
        return approvalAction;
    }

    public String getApprovalDate() {
        return approvalDate;
    }

    public String getApprovalAdmin() {
        return approvalAdmin;
    }

    public String getApprovalComment() {
        return approvalComment;
    }

    public Boolean isCanApprove() {
        return canApprove;
    }

    public Integer getRemainingApprovals() {
        return remainingApprovals;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final ApprovalAccumulativeRestResponse response;

        private Builder() {
            response = new ApprovalAccumulativeRestResponse();
        }

        public Builder approvalAction(final String approvalAction) {
            response.approvalAction = approvalAction;
            return this;
        }

        public Builder approvalDate(final String approvalDate) {
            response.approvalDate = approvalDate;
            return this;
        }

        public Builder approvalAdmin(final String approvalAdmin) {
            response.approvalAdmin = approvalAdmin;
            return this;
        }

        public Builder approvalComment(final String approvalComment) {
            response.approvalComment = approvalComment;
            return this;
        }

        public Builder canApprove(final Boolean canApprove) {
            response.canApprove = canApprove;
            return this;
        }

        public Builder remainingApprovals(final Integer remainingApprovals) {
            response.remainingApprovals = remainingApprovals;
            return this;
        }

        public ApprovalAccumulativeRestResponse build() {
            return response;
        }

    }
}

