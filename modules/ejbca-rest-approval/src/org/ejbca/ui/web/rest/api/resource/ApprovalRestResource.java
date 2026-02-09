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

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRequestsSearchRequest;
import org.ejbca.core.model.era.RaRequestsSearchResponse;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchApprovalRestResponse;

import java.util.List;

import static org.ejbca.core.model.approval.ApprovalDataVO.APPROVALTYPENAMES;

/**
 * JAX-RS resource handling approval-related requests.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalRestResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(ApprovalRestResource.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;

    /**
     * Gets the status of an approval request.
     *
     * @param requestContext the HTTP request context
     * @param requestId      the ID of the approval request
     * @return Approval request status
     * @throws RestException if the request ID is invalid or not found
     */
    public Response getApprovalRequestStatus(final HttpServletRequest requestContext, final int requestId) throws RestException {
        if (requestId <= 0) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Invalid request ID '" + requestId + "'. Request ID must be a positive integer.");
        }

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
     * Search for approval requests.
     *
     * @param requestContext
     * @param searchApprovalRestRequest
     * @return
     * @throws RestException
     */
    public Response getApprovalSearchResults(@Context final HttpServletRequest requestContext,
                                             @Valid @NotNull final SearchApprovalRestRequest searchApprovalRestRequest) throws RestException {

        RaRequestsSearchRequest raRequestsSearchRequest = convertSearchPendingApprovalRestRequestToRaRequestsSearchRequest(searchApprovalRestRequest);

        try {
            final AuthenticationToken authenticationToken = getAdmin(requestContext, false);

            RaRequestsSearchResponse raRequestsSearchResponse = raMasterApi.searchForApprovalRequests(authenticationToken, raRequestsSearchRequest);

            List<RaApprovalRequestInfo> approvalRequestInfoList = raRequestsSearchResponse.getApprovalRequests();

            List<SearchApprovalRestResponse> searchApprovalRestResponses = new java.util.ArrayList<>();

            for (RaApprovalRequestInfo approvalRequestInfo : approvalRequestInfoList) {
                final SearchApprovalRestResponse searchApprovalRestResponse =
                        SearchApprovalRestResponse.builder()
                                .requestId(approvalRequestInfo.getId())
                                .requestDate(approvalRequestInfo.getApprovalData().getRequestDate())
                                .expirationDate(approvalRequestInfo.getApprovalData().getExpireDate())
                                .requestType(toHumanReadableApprovalTypeName(approvalRequestInfo.getApprovalData().getApprovalType()))
                                .requestedBy(approvalRequestInfo.getApprovalData().getApprovalRequest().getRequestAdmin().toString())
                                .build();
                searchApprovalRestResponses.add(searchApprovalRestResponse);
            }
            return Response.ok(searchApprovalRestResponses).build();

        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }
    }


    private RaRequestsSearchRequest convertSearchPendingApprovalRestRequestToRaRequestsSearchRequest(SearchApprovalRestRequest searchApprovalRestRequest) {
        RaRequestsSearchRequest raRequestsSearchRequest = new RaRequestsSearchRequest();
        raRequestsSearchRequest.setSearchingPending(searchApprovalRestRequest.isSearchingPending());
        raRequestsSearchRequest.setCustomSearchSubjectDn(searchApprovalRestRequest.getSubjectDn());
        raRequestsSearchRequest.setCustomSearchEmail(searchApprovalRestRequest.getEmail());
        raRequestsSearchRequest.setStartDate(searchApprovalRestRequest.getStartDate());
        raRequestsSearchRequest.setEndDate(searchApprovalRestRequest.getEndDate());
        raRequestsSearchRequest.setExpiresBefore(searchApprovalRestRequest.getExpiresBefore());
        raRequestsSearchRequest.setIncludeOtherAdmins(searchApprovalRestRequest.isIncludeOtherAdmins());
        raRequestsSearchRequest.setSearchingHistorical(searchApprovalRestRequest.isSearchingHistorical());
        raRequestsSearchRequest.setSearchingExpired(searchApprovalRestRequest.isSearchingExpired());
        raRequestsSearchRequest.setSearchingWaitingForMe(searchApprovalRestRequest.isSearchingWaitingForMe());
        return raRequestsSearchRequest;
    }


    private static String toHumanReadableApprovalTypeName(final int approvalType) {
        return switch (APPROVALTYPENAMES.get(approvalType)) {
            case "APDUMMY" -> "Dummy";
            case "APADDENDENTITY" -> "Add End Entity";
            case "APEDITENDENTITY" -> "Edit End Entity";
            case "APCHANGESTATUSENDENTITY" -> "Change Status of End Entity";
            case "APKEYRECOVERY" -> "Key Recover";
            case "APGENERATETOKEN" -> "Generate Token";
            case "APREVOKEENDENTITY" -> "Revoke End Entity";
            case "APREVOKEDELETEENDENTITY" -> "Revoke and Delete End Entity";
            case "APREVOKECERTIFICATE" -> "Revoke or Reactivate Certificate";
            case "APPROVEACTIVATECA" -> "CA Service Activation";
            default -> "Unknown (" + approvalType + "): " + APPROVALTYPENAMES.get(approvalType);
        };
    }

}
