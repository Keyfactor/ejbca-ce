/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Response containing the result of processing an approval request.
 */
@Schema(name = "ProcessApprovalRestResponse", description = "Response after processing an approval request")
public class ProcessApprovalRestResponse {

    @Schema(description = "The unique identifier of the approval request", example = "1234")
    private String requestId;

    @Schema(description = "The type of the approval request", example = "Add End Entity")
    private String requestType;

    @Schema(description = "The date when the request was created", example = "2025-01-01 13:59:00+01:00")
    private String requestDate;

    @Schema(description = "The date when the request expires", example = "2025-01-02 13:59:00+01:00")
    private String expirationDate;

    @Schema(description = "The end entity name associated with the request", example = "username")
    private String endEntityName;

    @Schema(description = "The current status of the approval request", example = "APPROVED")
    private String status;

    @Schema(description = "The list of approval steps with their status")
    private List<ApprovalStepRestResponse> steps;

    private ProcessApprovalRestResponse(final Builder builder) {
        this.requestId = builder.requestId;
        this.requestType = builder.requestType;
        this.requestDate = builder.requestDate;
        this.expirationDate = builder.expirationDate;
        this.endEntityName = builder.endEntityName;
        this.status = builder.status;
        this.steps = builder.steps;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getRequestType() {
        return requestType;
    }

    public String getRequestDate() {
        return requestDate;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public String getEndEntityName() {
        return endEntityName;
    }

    public String getStatus() {
        return status;
    }

    public List<ApprovalStepRestResponse> getSteps() {
        return steps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String requestId;
        private String requestType;
        private String requestDate;
        private String expirationDate;
        private String endEntityName;
        private String status;
        private List<ApprovalStepRestResponse> steps;

        public Builder requestId(final String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder requestType(final String requestType) {
            this.requestType = requestType;
            return this;
        }

        public Builder requestDate(final String requestDate) {
            this.requestDate = requestDate;
            return this;
        }

        public Builder expirationDate(final String expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

        public Builder endEntityName(final String endEntityName) {
            this.endEntityName = endEntityName;
            return this;
        }

        public Builder status(final String status) {
            this.status = status;
            return this;
        }

        public Builder steps(final List<ApprovalStepRestResponse> steps) {
            this.steps = steps;
            return this;
        }

        public ProcessApprovalRestResponse build() {
            return new ProcessApprovalRestResponse(this);
        }
    }
}
