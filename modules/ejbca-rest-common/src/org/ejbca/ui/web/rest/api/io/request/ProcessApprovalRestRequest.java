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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.ArrayList;
import java.util.List;
import org.ejbca.ui.web.rest.api.validator.ValidProcessApprovalRestRequest;

/**
 * JSON input for processing (approving/rejecting) an approval request.
 */
@ValidProcessApprovalRestRequest
@Schema(name = "ProcessApprovalRestRequest", description = "Request to process (approve or reject) an approval request")
public class ProcessApprovalRestRequest {

    @Schema(description = "Whether to approve (true) or reject (false) the request", required = true, example = "true")
    private Boolean approve;

    @Schema(description = "Optional comment for the approval/rejection action", example = "Approved after verification")
    private String comment;

    @Schema(description = "Partition list with properties provided on approving/rejecting partitioned approval request")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ApprovalPartitionRestRequest> approvalPartitions = new ArrayList<>();

    public ProcessApprovalRestRequest() {
    }

    public ProcessApprovalRestRequest(final Boolean approve, final String comment, final List<ApprovalPartitionRestRequest> approvalPartitions) {
        this.approve = approve;
        this.comment = comment;
        this.approvalPartitions = approvalPartitions;
    }

    public Boolean getApprove() {
        return approve;
    }

    public void setApprove(final Boolean approve) {
        this.approve = approve;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(final String comment) {
        this.comment = comment;
    }

    public List<ApprovalPartitionRestRequest> getApprovalPartitions() {
        return approvalPartitions;
    }

    public void setApprovalPartitions(final List<ApprovalPartitionRestRequest> approvalPartitions) {
        this.approvalPartitions = approvalPartitions;
    }
}
