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

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestStatusRestResponse;

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
}
