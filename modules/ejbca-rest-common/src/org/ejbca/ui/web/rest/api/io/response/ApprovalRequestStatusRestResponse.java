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
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import org.ejbca.core.model.approval.ApprovalRequestStatus;

/**
 * Response object for approval request status.
 */
@Schema(name = "ApprovalRequestStatusRestResponse", description = "Response containing approval request status")
public class ApprovalRequestStatusRestResponse {

    @Schema(description = "The request ID", example = "12345")
    @JsonInclude(JsonInclude.Include.ALWAYS)
    @JsonProperty("request_id")
    private int requestId;

    @Schema(description = "The status of the approval request",
            example = "PENDING",
            allowableValues = {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "EXPIRED_AND_NOTIFIED", "EXECUTED", "EXECUTION_FAILED", "EXECUTION_DENIED"})
    private ApprovalRequestStatus status;

    private ApprovalRequestStatusRestResponse(final Builder builder) {
        this.requestId = builder.requestId;
        this.status = builder.status;
    }

    public int getRequestId() {
        return requestId;
    }

    public void setRequestId(final int requestId) {
        this.requestId = requestId;
    }

    public ApprovalRequestStatus getStatus() {
        return status;
    }

    public void setStatus(final ApprovalRequestStatus status) {
        this.status = status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private int requestId;
        private ApprovalRequestStatus status;

        public Builder requestId(final int requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder status(final ApprovalRequestStatus status) {
            this.status = status;
            return this;
        }

        public ApprovalRequestStatusRestResponse build() {
            return new ApprovalRequestStatusRestResponse(this);
        }
    }
}
