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
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.core.EntityPart;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.CaInfosRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CreateCrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.resource.CaRestResource;

import jakarta.ejb.Stateless;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;

/**
 * JAX-RS resource handling CA related requests.
 */
@Tag(name = "v1/ca", description = "CA REST API")
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@OpenAPIDefinition(servers = @Server(url = "/ejbca/ejbca-rest-api", description = "HTTPS Server"))
@Stateless
public class CaRestResourceSwagger extends CaRestResource {

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

    @Override
    @GET
    @Path("/{subject_dn}/certificate/download")
    @Produces(MediaType.WILDCARD)
    @Operation(description = "Get PEM file with the active CA certificate chain")
    public Response getCertificateAsPem(@Context HttpServletRequest requestContext,
                                        @Parameter(name = "CAs subject DN", required = true) @PathParam("subject_dn") String subjectDn)
            throws AuthorizationDeniedException, CertificateEncodingException, CADoesntExistsException, RestException {
        return super.getCertificateAsPem(requestContext, subjectDn);
    }

    @Override
    @GET
    @Operation(summary = "Returns the Response containing the list of CAs with general information per CA as Json",
            description = "Returns the Response containing the list of CAs with general information per CA as Json",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CaInfosRestResponse.class))
                    )
            })
    public Response listCas(@Context final HttpServletRequest httpServletRequest,
            @Parameter(description = "true to get external (i.e. imported) cartificates, false to not get external (i.e. imported) certificates",
                    required = false,
                    schema = @Schema(type = "boolean", defaultValue = "false", example = "true"))
            @QueryParam("includeExternal") boolean includeExternal
            ) throws AuthorizationDeniedException,
            CADoesntExistsException, RestException {
        return super.listCas(httpServletRequest, includeExternal);
    }

    @Override
    @GET
    @Path("/{issuer_dn}/getLatestCrl")
    @Operation(description = "Returns the latest CRL issued by this CA",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content =  @Content(schema = @Schema(implementation = CrlRestResponse.class))
                    )
            })
    public Response getLatestCrl(@Context HttpServletRequest httpServletRequest,
                                 @Parameter(description = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                                 @Parameter(description = "true to get the latest deltaCRL, false to get the latest complete CRL", required = false,
                                         schema = @Schema(type = "boolean", defaultValue = "false", example = "true"))
                                 @QueryParam("deltaCrl") boolean deltaCrl,
                                 @Parameter(description = "the CRL partition index", required = false, schema = @Schema(type = "integer", defaultValue = "0"))
                                 @QueryParam("crlPartitionIndex") int crlPartitionIndex
    ) throws AuthorizationDeniedException, RestException, CADoesntExistsException {
        return super.getLatestCrl(httpServletRequest, issuerDn, deltaCrl, crlPartitionIndex);
    }

    @Override
    @POST
    @Path("/{issuer_dn}/createcrl")
    @Consumes(MediaType.APPLICATION_JSON)
    @Operation(description = "Create CRL(main, partition and delta) issued by this CA", responses = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful operation",
                    content = @Content(schema = @Schema(implementation = CreateCrlRestResponse.class))
            )
    })
    public Response createCrl(@Context HttpServletRequest httpServletRequest,
                              @Parameter(description = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                              @Parameter(description = "true to create the deltaCRL, false to create the base CRL", required = false,
                                      schema = @Schema(type = "boolean", defaultValue = "false", example = "true"))
                              @QueryParam("deltacrl") boolean deltacrl
    ) throws AuthorizationDeniedException, RestException, CADoesntExistsException {
        return super.createCrl(httpServletRequest, issuerDn, deltacrl);
    }

    @Override
    @POST
    @Path("/{issuer_dn}/importcrl")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(description = "Import a certificate revocation list (CRL) for a CA",
            responses = {
                    @ApiResponse(responseCode = "200", description = "CRL file was imported successfully"),
                    @ApiResponse(responseCode = "400", description = "Error while importing CRL file")
            })
    public Response importCrl(@Context final HttpServletRequest httpServletRequest,
                              @Parameter(description = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                              @Parameter(description = "CRL partition index", schema = @Schema(type = "integer", defaultValue = "0")) @FormParam("crlPartitionIndex") EntityPart crlPartitionIndexEP,
                              @Parameter(description = "CRL file in DER format", schema = @Schema(type="string", format="binary")) @FormParam("crlFile") final EntityPart crlFileEP
    ) throws AuthorizationDeniedException, RestException {
        return super.importCrl(httpServletRequest, issuerDn, crlPartitionIndexEP, crlFileEP);
    }
}
