/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.resource.swagger;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ejb.Stateless;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ProcessApprovalRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.resource.ApprovalRestResource;

/**
 * JAX-RS resource handling approval requests.
 */
@Tag(name = "v1/approval", description = "Approval Management REST API V1")
@Path("/v1/approval")
@Produces(MediaType.APPLICATION_JSON)
@OpenAPIDefinition(servers = @Server(url = "/ejbca/ejbca-rest-api", description = "HTTPS Server"))
@Stateless
public class ApprovalRestResourceSwagger extends ApprovalRestResource {

    @GET
    @Path("/status")
    @Operation(summary = "Get the status of this REST Resource",
            description = "Returns status, API version and EJBCA version.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = RestResourceStatusRestResponse.class))
                    )
            })
    @Override
    public Response status() {
        return super.status();
    }

    @POST
    @Path("/{request_id}/process")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Process (approve or reject) an approval request",
            description = "Allows an administrator to approve or reject an approval request given a request ID.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Approval request processed successfully",
                            content = @Content(schema = @Schema(implementation = ProcessApprovalRestResponse.class))
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Invalid request or approval request cannot be processed"
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Authentication required"
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Authorization denied"
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Approval request not found"
                    )
            })
    public Response processApprovalRequest(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "The ID of the approval request to process", required = true)
            @PathParam("request_id") int requestId,
            @Parameter(description = "The approval/rejection decision", required = true)
            ProcessApprovalRestRequest request
    ) throws AuthorizationDeniedException, RestException {
        return super.processApprovalRequest(requestContext, requestId, request);
    }
}
