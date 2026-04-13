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

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single approval partition in an approval request response.
 */
@Schema(name = "ApprovalPartitionRestResponse", description = "Information about approval partitions")
public class ApprovalPartitionRestResponse {

    @Schema(description = "List of approval partitions")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ApprovalPartitionStep> approvalPartitions = new ArrayList<>();

    public ApprovalPartitionRestResponse() {
    }

    public List<ApprovalPartitionStep> getApprovalPartitions() {
        return approvalPartitions;
    }

    public void setApprovalPartitions(final List<ApprovalPartitionStep> approvalPartitions) {
        this.approvalPartitions = approvalPartitions;
    }

    public static class ApprovalPartitionStep {

        @Schema(description = "Partition name", example = "Partition name")
        private String name;

        @Schema(description = "Partition identifier", example = "0123456")
        private int partitionIdentifier;

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
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private List<ApprovalPartitionPropertyRestResponse> propertyList = new ArrayList<>();

        public ApprovalPartitionStep() {
        }

        public String getName() {
            return name;
        }

        public int getPartitionIdentifier() {
            return partitionIdentifier;
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

            private final ApprovalPartitionStep response;

            private Builder() {
                response = new ApprovalPartitionStep();
            }

            public Builder name(final String name) {
                response.name = name;
                return this;
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

            public Builder propertyList(final List<ApprovalPartitionPropertyRestResponse> propertyList) {
                response.propertyList = propertyList;
                return this;
            }

            public Builder partitionIdentifier(final int partitionIdentifier) {
                response.partitionIdentifier = partitionIdentifier;
                return this;
            }

            public ApprovalPartitionStep build() {
                return response;
            }
        }
    }
}