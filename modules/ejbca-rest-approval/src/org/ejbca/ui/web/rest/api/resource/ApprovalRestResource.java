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

import java.util.List;

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
     * @param requestContext        the HTTP request context
     * @param requestId             the ID of the approval request
     * @return                      Approval request status
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

    public Response getApprovalSearchResutlts(@Context final HttpServletRequest requestContext,
                                              final SearchApprovalRestRequest searchApprovalRestRequest) throws RestException {

        RaRequestsSearchRequest raRequestsSearchRequest = convertSearchPendingApprovalRestRequestToRaRequestsSearchRequest(searchApprovalRestRequest);

        try {
            RaRequestsSearchResponse raRequestsSearchResponse = raMasterApi.searchForApprovalRequests(getAdmin(requestContext, false), raRequestsSearchRequest);

            List<RaApprovalRequestInfo> approvalRequestInfoList = raRequestsSearchResponse.getApprovalRequests();

            for (RaApprovalRequestInfo approvalRequestInfo : approvalRequestInfoList) {
                approvalRequestInfo.

            }



        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage(), e);
            throw new RestException(Response.Status.FORBIDDEN.getStatusCode(), "Missing or invalid authentication.");
        }

        return Response.ok().build();
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


}
