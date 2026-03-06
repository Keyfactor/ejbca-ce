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
import java.util.List;

/**
 * Represents a single approval partition in an approval request response.
 */
@Schema(name = "ApprovalPartitionRestResponse", description = "Information about an approval partition")

public class ApprovalPartitionRestResponse {

    @Schema(description = "The action taken on this step (e.g., APPROVED, REJECTED, PENDING)", example = "APPROVED")
    private String approvalAction;

    @Schema(description = "The date when the approval action was taken", example = "2025-01-01 14:55:00+01:00")
    private String approvalDate;

    @Schema(description = "The admin who performed the approval action", example = "CN=RAAdmin")
    private String approvalAdmin;

    @Schema(description = "Comment provided with the approval action", example = "Approved after verification")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String approvalComment;
    
    @Schema(description = "Partition properties provided with the approval action")
    List<ApprovalPartitionPropertyRestResponse> propertyList;

    public ApprovalPartitionRestResponse(final Builder builder) {
        this.propertyList = builder.propertyList;
        this.approvalAction = builder.approvalAction;
        this.approvalDate = builder.approvalDate;
        this.approvalAdmin = builder.approvalAdmin;
        this.approvalComment = builder.approvalComment;
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
    
    public List<ApprovalPartitionPropertyRestResponse> getPropertyList() {
        return propertyList;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String approvalAction;
        private String approvalDate;
        private String approvalAdmin;
        private String approvalComment;
        private List<ApprovalPartitionPropertyRestResponse> propertyList;
        public Builder approvalAction(final String approvalAction) {
            this.approvalAction = approvalAction;
            return this;
        }

        public Builder approvalDate(final String approvalDate) {
            this.approvalDate = approvalDate;
            return this;
        }

        public Builder approvalAdmin(final String approvalAdmin) {
            this.approvalAdmin = approvalAdmin;
            return this;
        }

        public Builder approvalComment(final String approvalComment) {
            this.approvalComment = approvalComment;
            return this;
        }

        public Builder propertyList(final List<ApprovalPartitionPropertyRestResponse> propertyList) {
            this.propertyList = propertyList;
            return this;
        }

        public ApprovalPartitionRestResponse build() {
            return new ApprovalPartitionRestResponse(this);
        }
        
    }
}
