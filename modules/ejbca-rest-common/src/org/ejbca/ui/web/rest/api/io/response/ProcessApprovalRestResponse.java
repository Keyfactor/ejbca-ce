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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestStatus;

import java.util.List;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalStepInfo;

/**
 * Response containing the result of processing an approval request.
 */
@Schema(name = "ProcessApprovalRestResponse", description = "Response after processing an approval request")
public class ProcessApprovalRestResponse {
    static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ssXXX";

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

    @Schema(description = "The status of the approval request",
            example = "PENDING",
            allowableValues = {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "EXPIRED_AND_NOTIFIED", "EXECUTED", "EXECUTION_FAILED", "EXECUTION_DENIED"})
    private ApprovalRequestStatus status;

    @Schema(description = "The list of approval steps with their status")
    private List<ApprovalStepRestResponse> steps;

    ProcessApprovalRestResponse(final Builder builder) {
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

    public ApprovalRequestStatus getStatus() {
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
        private ApprovalRequestStatus status;
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

        public Builder status(final ApprovalRequestStatus status) {
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

    public static ProcessApprovalRestResponse buildApprovalResponse(final RaApprovalRequestInfo requestInfo) {
        final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        final ApprovalDataVO approvalData = requestInfo.getApprovalData();
        final String endEntityName = getUsername(requestInfo.getApprovalRequest());

        // Build approval steps
        final List<ApprovalStepRestResponse> steps = buildApprovalSteps(requestInfo);

        final Date requestDate = new Date(approvalData.getRequestDate().getTime());
        final long expirationPeriod = requestInfo.getApprovalRequest().getRequestValidity();
        final Date expirationDate = new Date(requestDate.getTime() + expirationPeriod);

        return ProcessApprovalRestResponse.builder()
                .requestId(String.valueOf(requestInfo.getId()))
                .requestType(ApprovalType.getNameByCode(approvalData.getApprovalType()))
                .requestDate(dateFormat.format(requestDate))
                .expirationDate(dateFormat.format(expirationDate))
                .endEntityName(endEntityName)
                .status(ApprovalRequestStatus.fromIntWithCombinedStates(requestInfo.getStatus()))
                .steps(steps)
                .build();
    }

    static List<ApprovalStepRestResponse> buildApprovalSteps(final RaApprovalRequestInfo requestInfo) {
        final List<ApprovalStepRestResponse> steps = new ArrayList<>();
        final List<RaApprovalStepInfo> previousSteps = requestInfo.getPreviousApprovalSteps();

        if (previousSteps != null) {
            // Get all approvals from the approval data
            final ApprovalDataVO approvalData = requestInfo.getApprovalData();
            final Collection<Approval> approvals = approvalData.getApprovals();

            int stepNumber = 1;
            for (RaApprovalStepInfo stepInfo : previousSteps) {
                for (ApprovalPartition partition : stepInfo.getPartitions()) {
                    final ApprovalStepRestResponse.Builder stepBuilder = ApprovalStepRestResponse.builder()
                            .step(stepNumber);

                    // Find the approval record for this step and partition
                    Approval matchingApproval = null;
                    if (approvals != null) {
                        for (Approval approval : approvals) {
                            if (approval.getStepId() == stepInfo.getStepId() &&
                                    approval.getPartitionId() == partition.getPartitionIdentifier()) {
                                matchingApproval = approval;
                                //break;
                                // TODO Now we only display in the latest approving admin for this step (i.e. the one which sent this request)
                                // In the GUI we display all administrators that performed this step (accumulative profile)
                                // If we want to do the same for the REST API, we'd need to restructure the response objects JSON
                            }
                        }
                    }

                    // Populate approval details if found
                    if (matchingApproval != null) {
                        stepBuilder.approvalAction(matchingApproval.isApproved() ? "APPROVED" : "REJECTED");

                        if (matchingApproval.getApprovalDate() != null) {
                            stepBuilder.approvalDate(new SimpleDateFormat(DATE_FORMAT).format(matchingApproval.getApprovalDate()));
                        }

                        if (matchingApproval.getAdmin() != null) {
                            stepBuilder.approvalAdmin(matchingApproval.getAdmin().toString());
                        }

                        if (matchingApproval.getComment() != null && !matchingApproval.getComment().isEmpty()) {
                            stepBuilder.approvalComment(matchingApproval.getComment());
                        }
                    } else {
                        // Fallback if no matching approval found
                        stepBuilder.approvalAction("COMPLETED");
                    }
                    steps.add(stepBuilder.build());
                    stepNumber++;
                }
            }
        }
        return steps;
    }

    static String getUsername(final ApprovalRequest approvalRequest) {
        if (approvalRequest instanceof AddEndEntityApprovalRequest request) {
            return request.getEndEntityInformation().getUsername();
        } else if (approvalRequest instanceof EditEndEntityApprovalRequest request) {
            return request.getNewEndEntityInformation().getUsername();
        } else if (approvalRequest instanceof RevocationApprovalRequest request) {
            return request.getUsername();
        } else if (approvalRequest instanceof KeyRecoveryApprovalRequest request) {
            return request.getUsername();
        } else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest request) {
            return request.getUsername();
        } else {
            return null;
        }
    }
}
