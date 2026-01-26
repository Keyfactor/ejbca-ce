/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import jakarta.ejb.Stateless;
import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.model.approval.*;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaApprovalStepInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ApprovalStepRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ProcessApprovalRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * JAX-RS resource handling approval request operations.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalRestResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(ApprovalRestResource.class);

    private static final String RESOURCE_STATUS = "OK";
    protected static final String RESOURCE_VERSION = "1.0";
    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ssXXX";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;


    /**
     * Processes an approval request by approving or rejecting it.
     *
     * @param requestContext the HTTP servlet request context
     * @param requestId the ID of the approval request to process
     * @param request the request body containing the approval decision
     * @return Response containing the updated approval request information
     * @throws AuthorizationDeniedException if the admin is not authorized
     * @throws RestException if the request is invalid or processing fails
     */
    public Response processApprovalRequest(
            final HttpServletRequest requestContext,
            final int requestId,
            @Valid final ProcessApprovalRestRequest request)
            throws AuthorizationDeniedException, RestException {

        final AuthenticationToken admin = getAdmin(requestContext, false);

        if (request == null || request.getApprove() == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Request body must contain 'approve' field");
        }

        // Retrieve the approval request
        final RaApprovalRequestInfo approvalRequestInfo = raMasterApiProxy.getApprovalRequest(admin, requestId);
        if (approvalRequestInfo == null) {
            throw new RestException(Response.Status.NOT_FOUND.getStatusCode(),
                    "Approval request with ID " + requestId + " not found or access denied");
        }

        // Check if the request can be processed
        final int status = approvalRequestInfo.getStatus();
        if (status != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            final String statusName = getStatusName(status);
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Approval request cannot be processed. Current status: " + statusName);
        }

        // Get the next approval step and partition
        final ApprovalPartition nextPartition = approvalRequestInfo.getNextApprovalStepPartition();
        if (nextPartition == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "No approval step available for processing");
        }

        try {
            final RaApprovalResponseRequest.Action action = request.getApprove() 
                    ? RaApprovalResponseRequest.Action.APPROVE 
                    : RaApprovalResponseRequest.Action.REJECT;
            
            final RaApprovalResponseRequest responseRequest = new RaApprovalResponseRequest(
                    requestId,
                    approvalRequestInfo.getNextApprovalStep().getStepIdentifier(),
                    nextPartition.getPartitionIdentifier(),
                    approvalRequestInfo.getApprovalRequest(),
                    request.getComment() != null ? request.getComment() : "",
                    action
            );
            
            raMasterApiProxy.addRequestResponse(admin, responseRequest);
            
            if (request.getApprove()) {
                log.info("Administrator " + admin + " approved approval request with ID " + requestId);
            } else {
                log.info("Administrator " + admin + " rejected approval request with ID " + requestId);
            }
        } catch (ApprovalRequestExpiredException e) {
            log.info("Approval request " + requestId + " has expired");
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Approval request has expired");
        } catch (ApprovalRequestExecutionException e) {
            log.info("Error executing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Error executing approval request: " + e.getMessage());
        } catch (ApprovalException e) {
            log.info("Error processing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Error processing approval request: " + e.getMessage());
        } catch (Exception e) {
            log.info("Unexpected error processing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Unexpected error processing approval request: " + e.getMessage());
        }

        // Retrieve the updated approval request info to populate response object
        final RaApprovalRequestInfo updatedRequestInfo = raMasterApiProxy.getApprovalRequest(admin, requestId);
        if (updatedRequestInfo == null) {
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Failed to retrieve updated approval request information");
        }

        // Build the response
        final ProcessApprovalRestResponse response = buildApprovalResponse(updatedRequestInfo);
        return Response.ok(response).build();
    }

    private EndEntityInformation getEndEntityInformation(ApprovalRequest approvalRequest) {
        if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            return ((AddEndEntityApprovalRequest)approvalRequest).getEndEntityInformation();
        } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            return ((EditEndEntityApprovalRequest)approvalRequest).getNewEndEntityInformation();
        } else {
            return null;
        }
    }

    private ProcessApprovalRestResponse buildApprovalResponse(final RaApprovalRequestInfo requestInfo) {
        final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        final ApprovalDataVO approvalData = requestInfo.getApprovalData();

        String endEntityName = getEndEntityInformation(requestInfo.getApprovalRequest()).getUsername();

        // Build approval steps
        final List<ApprovalStepRestResponse> steps = buildApprovalSteps(requestInfo, dateFormat);

        // Calculate expiration date
        final Date requestDate = new Date(approvalData.getRequestDate().getTime());
        final long expirationPeriod = requestInfo.getApprovalRequest().getRequestValidity();
        final Date expirationDate = new Date(requestDate.getTime() + expirationPeriod);

        return ProcessApprovalRestResponse.builder()
                .requestId(String.valueOf(requestInfo.getId()))
                .requestType(getApprovalTypeName(approvalData.getApprovalType()))
                .requestDate(dateFormat.format(requestDate))
                .expirationDate(dateFormat.format(expirationDate))
                .endEntityName(endEntityName)
                .status(getStatusName(requestInfo.getStatus()))
                .steps(steps)
                .build();
    }

    private List<ApprovalStepRestResponse> buildApprovalSteps(final RaApprovalRequestInfo requestInfo, final SimpleDateFormat dateFormat) {

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
                                break;
                            }
                        }
                    }

                    // Populate approval details if found
                    if (matchingApproval != null) {
                        stepBuilder.approvalAction(matchingApproval.isApproved() ? "APPROVED" : "REJECTED");

                        if (matchingApproval.getApprovalDate() != null) {
                            stepBuilder.approvalDate(dateFormat.format(matchingApproval.getApprovalDate()));
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

    private String getStatusName(final int status) {
        switch (status) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                return "PENDING";
            case ApprovalDataVO.STATUS_APPROVED:
                return "APPROVED";
            case ApprovalDataVO.STATUS_REJECTED:
                return "REJECTED";
            case ApprovalDataVO.STATUS_EXPIRED:
                return "EXPIRED";
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                return "EXPIRED_AND_NOTIFIED";
            case ApprovalDataVO.STATUS_EXECUTED:
                return "EXECUTED";
            case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                return "EXECUTION_FAILED";
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                return "EXECUTION_DENIED";
            default:
                return "UNKNOWN";
        }
    }

    private String getApprovalTypeName(final int approvalType) {
        switch (approvalType) {
            case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY:
                return "Add End Entity";
            case ApprovalDataVO.APPROVALTYPE_EDITENDENTITY:
                return "Edit End Entity";
            case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY:
                return "Revoke End Entity";
            case ApprovalDataVO.APPROVALTYPE_CHANGESTATUSENDENTITY:
                return "Change Status of End Entity";
            case ApprovalDataVO.APPROVALTYPE_KEYRECOVERY:
                return "Key Recovery";
            case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE:
                return "Revoke Certificate";
            case ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY:
                return "Revoke and Delete End Entity";
            case ApprovalDataVO.APPROVALTYPE_ACME_ACCOUNT_KEYCHANGE:
                return "ACME Account Key Change";
            case ApprovalDataVO.APPROVALTYPE_ACME_ACCOUNT_REGISTRATION:
                return "ACME Account Registration";
            case ApprovalDataVO.APPROVALTYPE_ACTIVATECATOKEN:
                return "Activate CA Token";
            default:
                return "Unknown Type (" + approvalType + ")";
        }
    }
}
