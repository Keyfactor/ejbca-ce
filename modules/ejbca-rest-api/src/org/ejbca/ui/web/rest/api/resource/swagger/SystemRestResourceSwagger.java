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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ejb.Stateless;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.resource.SystemRestResource;


@Tag(name = "v1/system", description = "System REST Management API")
@Path("/v1/system")
@Produces(MediaType.APPLICATION_JSON)
@OpenAPIDefinition(servers = {@Server(url = "/ejbca/ejbca-rest-api", description = "HTTPS Server")})
@Stateless

public class SystemRestResourceSwagger extends SystemRestResource {
    @PUT
    @Path("/service/{service_name}/run")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Runs a specified service", description = "Run service with the provided name", responses = {
            @ApiResponse(
                    responseCode = "200",
                    description = "OK Successful request"
            )
    })
    public Response runServiceNoTimer(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Name of the service to run")
            @PathParam("service_name") String serviceName) throws AuthorizationDeniedException, RestException {
        return super.runServiceWorker(requestContext, serviceName);
    }
}
