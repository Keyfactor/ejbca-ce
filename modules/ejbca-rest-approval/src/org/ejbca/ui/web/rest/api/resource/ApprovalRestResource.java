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
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ProcessApprovalRestResponse;


/**
 * JAX-RS resource handling approval request operations.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalRestResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(ApprovalRestResource.class);


    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;


    /**
     * Gets the status of an approval request.
     *
     * @param requestContext        the HTTP request context
     * @param requestId             the ID of the approval request
     * @return                      Approval request status
     * @throws RestException if the request ID is invalid or not found
     */
    public Response getApprovalRequestStatus(final HttpServletRequest requestContext, final int requestId) throws RestException {
        validateRequestId(requestId);

        try {
            final AuthenticationToken authenticationToken = getAdmin(requestContext, false);
            final RaApprovalRequestInfo approvalRequestInfo = raMasterApi.getApprovalRequest(authenticationToken, requestId);

            // getApprovalRequest also returns null if the user is not authorized to view the request.
            if (approvalRequestInfo == null) {
                throw new RestException(
                        Response.Status.NOT_FOUND.getStatusCode(),
                        "Approval request with ID '" + requestId + "' not found, or user not authorized to view.");
            }

            final ApprovalRequestStatus status = ApprovalRequestStatus.fromIntWithCombinedStates(approvalRequestInfo.getStatus());
            final ApprovalRequestStatusRestResponse response = ApprovalRequestStatusRestResponse.builder()
                    .requestId(requestId)
                    .status(status)
                    .build();

            return Response.ok(response).build();
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }

    }


    /**
     * Gets the status of an approval request.
     *
     * @param requestContext        the HTTP request context
     * @param requestId             the ID of the approval request
     * @return                      Approval request status
     * @throws RestException if the request ID is invalid or not found
     */
    public Response getApprovalRequest(final HttpServletRequest requestContext, final int requestId) throws RestException {
        validateRequestId(requestId);

        try {
            final AuthenticationToken authenticationToken = getAdmin(requestContext, false);
            final RaApprovalRequestInfo approvalRequestInfo = raMasterApi.getApprovalRequest(authenticationToken, requestId);

            // getApprovalRequest also returns null if the user is not authorized to view the request.
            if (approvalRequestInfo == null) {
                throw new RestException(
                        Response.Status.NOT_FOUND.getStatusCode(),
                        "Approval request with ID '" + requestId + "' not found, or user not authorized to view.");
            }

            final ApprovalRequestRestResponse response = ApprovalRequestRestResponse.buildApprovalResponse(approvalRequestInfo);
            return Response.ok(response).build();
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }

    }

    private static void validateRequestId(int requestId) throws RestException {
        if (requestId <= 0) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid request ID '" + requestId + "'. Request ID must be a positive integer.");
        }
    }

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

        // Retrieve the approval request
        final RaApprovalRequestInfo approvalRequestInfo = raMasterApi.getApprovalRequest(admin, requestId);
        if (approvalRequestInfo == null) {
            throw new RestException(Response.Status.NOT_FOUND.getStatusCode(),
                    "Approval request with ID " + requestId + " not found or unauthorized");
        }

        // Check if the request can be processed
        final int status = approvalRequestInfo.getStatus();
        if (status != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            final String statusName = ApprovalRequestStatus.fromIntWithCombinedStates(status).toString();
            throw new RestException(Response.Status.CONFLICT.getStatusCode(),
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

            // Process the approval request
            raMasterApi.addRequestResponse(admin, responseRequest);
        } catch (ApprovalRequestExpiredException e) {
            log.info("Approval request " + requestId + " has expired");
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Approval request has expired");
        } catch (ApprovalRequestExecutionException e) {
            log.info("Error executing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Error executing approval request: " + e.getMessage());
        } catch (ApprovalException | AdminAlreadyApprovedRequestException | SelfApprovalException e) {
            log.info("Error processing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Error processing approval request: " + e.getMessage());
        } catch (Exception e) {
            log.info("Unexpected error processing approval request " + requestId + ": " + e.getMessage());
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Unexpected error processing approval request: " + e.getMessage());
        }

        // Retrieve the updated approval request info to populate response object
        final RaApprovalRequestInfo updatedRequestInfo = raMasterApi.getApprovalRequest(admin, requestId);
        if (updatedRequestInfo == null) {
            throw new RestException(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                    "Failed to retrieve updated approval request information");
        }

        // Build the response
        final ProcessApprovalRestResponse response = ProcessApprovalRestResponse.buildApprovalResponse(updatedRequestInfo);
        return Response.ok(response).build();
    }

}
