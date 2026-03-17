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
 * Represents a single approval step in an approval request response.
 */
@Schema(name = "ApprovalStepRestResponse", description = "Information about an approval step")
public class ApprovalStepRestResponse {

    @Schema(description = "The step number", example = "1")
    private int stepNumber;

    
    @Schema(description = "Partitions provided with the approval step")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private List<ApprovalPartitionRestResponse.ApprovalPartitionStep> partitionList;


    private ApprovalStepRestResponse(final Builder builder) {
        this.stepNumber = builder.stepNumber;
        this.partitionList = builder.partitionList;
    }

    public int getStepNumber() {
        return stepNumber;
    }

    public List<ApprovalPartitionRestResponse.ApprovalPartitionStep> getPartitionList() {
        return partitionList;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private int stepNumber;
        private List<ApprovalPartitionRestResponse.ApprovalPartitionStep> partitionList;

        public Builder stepNumber(final int step) {
            this.stepNumber = step;
            return this;
        }

        public Builder partitionList(final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> partitionList) {
            this.partitionList = partitionList;
            return this;
        }

        public ApprovalStepRestResponse build() {
            return new ApprovalStepRestResponse(this);
        }
    }
}
