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

package org.ejbca.ui.web.rest.api.resource;

import jakarta.ejb.Stateless;
import jakarta.ejb.EJB;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
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
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRequestsSearchRequest;
import org.ejbca.core.model.era.RaRequestsSearchResponse;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ProcessApprovalRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchApprovalRestResponse;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;


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
            log.info(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }

    }

    /**
     * Search for approval requests.
     *
     * @param requestContext
     * @param searchApprovalRestRequest
     * @return
     * @throws RestException
     */
    public Response getApprovalSearchResults(@Context final HttpServletRequest requestContext,
                                             @Valid @NotNull final SearchApprovalRestRequest searchApprovalRestRequest) throws RestException {

        RaRequestsSearchRequest raRequestsSearchRequest = convertSearchApprovalRestRequestToRaRequestsSearchRequest(searchApprovalRestRequest);

        try {
            final AuthenticationToken authenticationToken = getAdmin(requestContext, false);

            RaRequestsSearchResponse raRequestsSearchResponse = raMasterApi.searchForApprovalRequests(authenticationToken, raRequestsSearchRequest);

            List<RaApprovalRequestInfo> approvalRequestInfoList = raRequestsSearchResponse.getApprovalRequests();

            final SearchApprovalRestResponse searchApprovalRestResponse = new SearchApprovalRestResponse();

            for (RaApprovalRequestInfo approvalRequestInfo : approvalRequestInfoList) {
                final SearchApprovalRestResponse.Approval approval = SearchApprovalRestResponse.Approval.builder()
                        .requestId(approvalRequestInfo.getId())
                        .requestDate(approvalRequestInfo.getApprovalData().getRequestDate())
                        .expirationDate(approvalRequestInfo.getApprovalData().getExpireDate())
                        .requestType(getApprovalTypeName(approvalRequestInfo.getApprovalData().getApprovalType()))
                        .requestedBy(getRequesterAdmin(approvalRequestInfo.getApprovalData().getApprovalRequest().getRequestAdmin().toString()))
                        .canBeApprovedByMe(isAdminAbleToApproveTheRequest(approvalRequestInfo))
                        .approvalStatus(ApprovalRequestStatus.fromIntWithCombinedStates(approvalRequestInfo.getStatus()).getValue())
                        .build();
                searchApprovalRestResponse.getApprovals().add(approval);
            }
            return Response.ok(searchApprovalRestResponse).build();

        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }
    }

    private boolean isAdminAbleToApproveTheRequest(final RaApprovalRequestInfo approvalRequestInfo) {
        final ApprovalStep nextApprovalStep = approvalRequestInfo.getNextApprovalStep();

        final boolean allowSelfEdit = approvalRequestInfo.getApprovalRequest().getApprovalProfile().getAllowSelfEdit();
        return nextApprovalStep != null && (!approvalRequestInfo.isEditedByMe() || allowSelfEdit) && !approvalRequestInfo.isApprovedByMe() && !approvalRequestInfo.isRequestedByMe();

    }

    private RaRequestsSearchRequest convertSearchApprovalRestRequestToRaRequestsSearchRequest(SearchApprovalRestRequest searchApprovalRestRequest) throws RestException {
        RaRequestsSearchRequest raRequestsSearchRequest = new RaRequestsSearchRequest();
        raRequestsSearchRequest.setSearchingPending(searchApprovalRestRequest.isSearchingWaiting()); // Adapt the behaviour of Custom Search in RA GUI
        raRequestsSearchRequest.setCustomSearchSubjectDn(searchApprovalRestRequest.getSubjectDn());
        raRequestsSearchRequest.setCustomSearchEmail(searchApprovalRestRequest.getEmail());
        try {

            String createdOnOrAfter = searchApprovalRestRequest.getCreatedOnOrAfter();

            if (createdOnOrAfter != null) {
                createdOnOrAfter = createdOnOrAfter.trim();
                if (!createdOnOrAfter.isEmpty()) {
                    raRequestsSearchRequest.setStartDate(
                            new SimpleDateFormat("yyyy-MM-dd").parse(createdOnOrAfter)
                    );
                }
            }

        } catch (ParseException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid start date provided in the request.");
        }

        raRequestsSearchRequest.setEndDate(getProperSearchEndDate(searchApprovalRestRequest.getCreatedOnOrBefore()));
        if (StringUtils.isNoneBlank(searchApprovalRestRequest.getDaysRequestsExpireIn())) {
            raRequestsSearchRequest.setExpiresBefore(getDateBeforeExpiration(searchApprovalRestRequest.getDaysRequestsExpireIn()));
            raRequestsSearchRequest.setSearchingHistorical(false);
            raRequestsSearchRequest.setSearchingExpired(false);
            raRequestsSearchRequest.setSearchingWaitingForMe(true);
        } else {
            raRequestsSearchRequest.setSearchingHistorical(searchApprovalRestRequest.isSearchingProcessed());
            raRequestsSearchRequest.setSearchingExpired(searchApprovalRestRequest.isSearchingExpired());
            raRequestsSearchRequest.setSearchingWaitingForMe(searchApprovalRestRequest.isSearchingWaiting());
        }
        raRequestsSearchRequest.setIncludeOtherAdmins(true); // Adapt the behaviour of Custom Search in RA GUI
        return raRequestsSearchRequest;
    }

    private Date getProperSearchEndDate(final String createdOnOrBefore) throws RestException {
        if (!StringUtils.isBlank(createdOnOrBefore)) {
            final Calendar cal = Calendar.getInstance();
            try {
                cal.setTime(new SimpleDateFormat("yyyy-MM-dd").parse(createdOnOrBefore.trim()));
            } catch (ParseException e) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid end date provided in the request.");
            }
            cal.add(Calendar.DAY_OF_MONTH, 1);
            return cal.getTime();
        } else {
            return null;
        }
    }

    private String getRequesterAdmin(final String adminDn) {
        return adminDn.startsWith("CN=")
                ? adminDn.substring("CN=".length())
                : adminDn;
    }

    private Date getDateBeforeExpiration(final String customSearchExpiresDays) throws RestException {
        if (customSearchExpiresDays == null || customSearchExpiresDays.isBlank()) {
            return null;
        }
        final int days;
        try {
            days = Integer.parseInt(customSearchExpiresDays.trim());
        } catch (NumberFormatException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid days_requests_expire_in '" + customSearchExpiresDays + "'. Must be a non-negative integer.");
        }

        if (days < 0) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid days_requests_expire_in '" + customSearchExpiresDays + "'. Must be a non-negative integer.");
        }

        final Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());
        cal.add(Calendar.DAY_OF_MONTH, days);
        return cal.getTime();
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

    /**
     * Gets the data of an approval request.
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
