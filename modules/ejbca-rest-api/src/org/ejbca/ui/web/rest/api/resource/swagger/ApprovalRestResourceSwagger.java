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
package org.ejbca.ui.web.rest.api.resource.swagger;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
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
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ProcessApprovalRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ApprovalRequestStatusRestResponse;
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
                            description = "Successful response",
                            content = @Content(schema = @Schema(implementation = RestResourceStatusRestResponse.class))
                    )
            })
    @Override
    public Response status() {
        return super.status();
    }

    @GET
    @Path("/{request_id}/status")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Get the status of an approval request",
            description = "Returns the status of the specified approval request. \n Possible status values: PENDING, APPROVED, REJECTED, EXPIRED. ",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Approval request status retrieved successfully",
                            content = @Content(schema = @Schema(implementation = ApprovalRequestStatusRestResponse.class),
                                    examples = {
                                            @ExampleObject(name = "Pending", value = "{\"request_id\": 12345, \"status\": \"PENDING\"}"),
                                            @ExampleObject(name = "Approved", value = "{\"request_id\": 12345, \"status\": \"APPROVED\"}"),
                                            @ExampleObject(name = "Rejected", value = "{\"request_id\": 12345, \"status\": \"REJECTED\"}")
                                    })
                    ),
                    @ApiResponse(responseCode = "400", description = "Invalid request ID provided", content = @Content),
                    @ApiResponse(responseCode = "403", description = "Authorization denied", content = @Content),
                    @ApiResponse(responseCode = "404", description = "Approval request not found", content = @Content)
            })
    public Response getApprovalRequestStatus(
            @Context final HttpServletRequest requestContext,
            @Parameter(description = "The ID of the approval request", required = true, example = "12345")
            @PathParam("request_id") final int requestId) throws RestException {

        return super.getApprovalRequestStatus(requestContext, requestId);
    }

    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Get the approval data for this admin",
            description = "Returns approval data for to the current admin.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful search of approval data",
                            content = @Content(schema = @Schema(implementation = SearchApprovalRestRequest.class))
                    ),
                    @ApiResponse(responseCode = "400", description = "Invalid search data provided", content = @Content),
                    @ApiResponse(responseCode = "403", description = "Authorization denied for the current admin", content = @Content)
            })
    public Response getSearchResults(@Context HttpServletRequest requestContext, final SearchApprovalRestRequest searchApprovalRestRequest) throws RestException {
        return super.getApprovalSearchResults(requestContext, searchApprovalRestRequest);
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
                    ),
                    @ApiResponse(
                            responseCode = "409",
                            description = "Approval request cannot be processed due to current status"
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

    @GET
    @Path("/{request_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Get approval request data",
            description = "Returns the specified approval request. ",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Approval request retrieved successfully",
                            content = @Content(schema = @Schema(implementation = ApprovalRequestRestResponse.class))
                    ),
                    @ApiResponse(responseCode = "400", description = "Invalid request ID provided", content = @Content),
                    @ApiResponse(responseCode = "403", description = "Authorization denied", content = @Content),
                    @ApiResponse(responseCode = "404", description = "Approval request not found", content = @Content)
            })
    public Response getApprovalRequest(
            @Context final HttpServletRequest requestContext,
            @Parameter(description = "The ID of the approval request", required = true, example = "12345")
            @PathParam("request_id") final int requestId) throws RestException {

        return super.getApprovalRequest(requestContext, requestId);
    }
}
