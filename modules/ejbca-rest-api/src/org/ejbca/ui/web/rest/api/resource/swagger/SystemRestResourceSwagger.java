package org.ejbca.ui.web.rest.api.resource.swagger;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.resource.SystemRestResource;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;


@Api(tags = {"v1/system"}, value = "System REST Management API")
@Path("/v1/system")
@Produces(MediaType.APPLICATION_JSON)
@SwaggerDefinition(basePath = "/ejbca/ejbca-rest-api", schemes = {Scheme.HTTPS})
@Stateless

public class SystemRestResourceSwagger extends SystemRestResource {
    @PUT
    @Path("/service/{service_name}/run")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Runs a specified service", notes = "Run service with the provided name")
    @ApiResponses(value = {@ApiResponse(code = 200, message = "OK Successful request")})
    public Response runServiceNoTimer(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Name of the service to run")
            @PathParam("service_name") String serviceName) throws AuthorizationDeniedException, RestException {
        return super.runServiceWorker(requestContext, serviceName);
    }
}
