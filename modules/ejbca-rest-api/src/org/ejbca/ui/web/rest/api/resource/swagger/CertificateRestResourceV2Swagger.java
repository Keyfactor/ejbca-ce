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
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
import org.ejbca.ui.web.rest.api.io.response.CertificateCountResponse;
import org.ejbca.ui.web.rest.api.io.response.CertificateProfileInfoRestResponseV2;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponseV2;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResourceV2;

import jakarta.ejb.Stateless;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

/**
 * JAX-RS resource handling Certificate related requests.
 */
@Tag(name = "v2/certificate", description = "Certificate REST Management API")
@Path("v2/certificate")
@OpenAPIDefinition(
        /* @Info annotation seems to work properly only when it is configured only once. Must not specify it on any other RestResources in this module! */
        info = @Info(
                title = "EJBCA REST Interface",
                version = BaseRestResource.RESOURCE_VERSION,
                description = "API reference documentation."
        ),
        servers = @Server(url = "/ejbca/ejbca-rest-api", description = "HTTPS Server")
)
@Stateless
public class CertificateRestResourceV2Swagger extends CertificateRestResourceV2 {

    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
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

    @GET
    @Path("/count")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "Get the quantity of rather total issued or active certificates",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CertificateCountResponse.class))
                    )
            })
    @Override
    public Response getCertificateCount(@Context HttpServletRequest requestContext,
                                        @Parameter(description = "true if an active certificates should be counted only")
                                        @QueryParam("isActive") Boolean isActive
    ) throws AuthorizationDeniedException, RestException {
        return super.getCertificateCount(requestContext, isActive);
    }

    @Override
    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Searches for certificates confirming given criteria and pagination.",
            description = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchCertificateCriteriaRestRequestV2 model. Use -1 for current_page to get total number of certificate for the request criteria.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = SearchCertificatesRestResponseV2.class))
                    )
            })
    public Response searchCertificates(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Collection of search criterias and pagination information.") final SearchCertificatesRestRequestV2 searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException, CertificateParsingException {
        return super.searchCertificates(requestContext, searchCertificatesRestRequest);
    }

    @Override
    @GET
    @Path("/profile/{profile_name}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "Get Certificate Profile Info.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Sucessful operation",
                            content = @Content(schema = @Schema(implementation = CertificateProfileInfoRestResponseV2.class))
                    )
            })
    public Response getCertificateProfileInfo(
            @Context HttpServletRequest requestContext,
            @PathParam("profile_name") String certProfileName
            ) throws AuthorizationDeniedException, RestException {
        return super.getCertificateProfileInfo(requestContext, certProfileName);
    }

    @Override
    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/keyrecover")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "Marks certificate for  key recovery.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Certificate marked for key recovery successfully"),
            @ApiResponse(responseCode = "500", description = "General error, while trying to mark the certificate for key recovery"),})
    public Response markCertificateForKeyRecovery(@Context HttpServletRequest requestContext,
                                                  @Parameter(description = "Subject DN of the issuing CA") @PathParam("issuer_dn") String issuerDN,
                                                  @Parameter(description = "Hex serial number (without prefix, e.g. '00')") @PathParam("certificate_serial_number") String certificateSerialNumber)
            throws CADoesntExistsException, AuthorizationDeniedException, RestException, EjbcaException, WaitingForApprovalException {
        return super.markCertificateForKeyRecovery(requestContext, certificateSerialNumber, issuerDN);
    }

}
