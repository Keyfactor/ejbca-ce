/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * JSON input for processing (approving/rejecting) an approval request.
 */
@Schema(name = "ProcessApprovalRestRequest", description = "Request to process (approve or reject) an approval request")
public class ProcessApprovalRestRequest {

    @Schema(description = "Whether to approve (true) or reject (false) the request", required = true, example = "true")
    private Boolean approve;

    @Schema(description = "Optional comment for the approval/rejection action", example = "Approved after verification")
    private String comment;

    public ProcessApprovalRestRequest() {
    }

    public ProcessApprovalRestRequest(final Boolean approve, final String comment) {
        this.approve = approve;
        this.comment = comment;
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
}
