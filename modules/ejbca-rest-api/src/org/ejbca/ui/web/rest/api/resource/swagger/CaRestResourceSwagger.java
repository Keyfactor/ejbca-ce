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

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.core.EjbcaException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.CaInfosRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CreateCrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.resource.CaRestResource;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.File;
import java.security.cert.CertificateEncodingException;

/**
 * JAX-RS resource handling CA related requests.
 */
@Api(tags = {"v1/ca"}, value = "CA REST API")
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@SwaggerDefinition(basePath = "/ejbca/ejbca-rest-api", schemes = {Scheme.HTTPS})
@Stateless
public class CaRestResourceSwagger extends CaRestResource {

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource",
            notes = "Returns status, API version and EJBCA version.",
            response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }

    @GET
    @Path("/{subject_dn}/certificate/download")
    @Produces(MediaType.WILDCARD)
    @ApiOperation(value = "Get PEM file with the active CA certificate chain")
    public Response getCertificateAsPem(@Context HttpServletRequest requestContext,
                                        @ApiParam(value = "CAs subject DN", required = true) @PathParam("subject_dn") String subjectDn)
            throws AuthorizationDeniedException, CertificateEncodingException, CADoesntExistsException, RestException {
        return super.getCertificateAsPem(requestContext, subjectDn);
    }

    @GET
    @ApiOperation(value = "Returns the Response containing the list of CAs with general information per CA as Json",
            notes = "Returns the Response containing the list of CAs with general information per CA as Json",
            response = CaInfosRestResponse.class)
    public Response listCas(@Context final HttpServletRequest httpServletRequest) throws AuthorizationDeniedException,
            CADoesntExistsException, RestException {
        return super.listCas(httpServletRequest);
    }

    @GET
    @Path("/{issuer_dn}/getLatestCrl")
    @ApiOperation(value = "Returns the latest CRL issued by this CA",
            response = CrlRestResponse.class)
    public Response getLatestCrl(@Context HttpServletRequest httpServletRequest,
                                 @ApiParam(value = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                                 @ApiParam(value = "true to get the latest deltaCRL, false to get the latest complete CRL", required = false, defaultValue = "false")
                                 @QueryParam("deltaCrl") boolean deltaCrl,
                                 @ApiParam(value = "the CRL partition index", required = false, defaultValue = "0")
                                 @QueryParam("crlPartitionIndex") int crlPartitionIndex
    ) throws AuthorizationDeniedException, RestException, EjbcaException, CADoesntExistsException {
        return super.getLatestCrl(httpServletRequest, issuerDn, deltaCrl, crlPartitionIndex);
    }

    @POST
    @Path("/{issuer_dn}/createcrl")
    @Consumes(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Create CRL(main, partition and delta) issued by this CA", response = CreateCrlRestResponse.class)
    public Response createCrl(@Context HttpServletRequest httpServletRequest,
                              @ApiParam(value = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                              @ApiParam(value = "true to also create the deltaCRL, false to only create the base CRL", required = false, defaultValue = "false")
                              @QueryParam("deltacrl") boolean deltacrl
    ) throws AuthorizationDeniedException, RestException, EjbcaException, CADoesntExistsException {
        return super.createCrl(httpServletRequest, issuerDn, deltacrl);
    }

    @POST
    @Path("/{issuer_dn}/importcrl")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Import a certificate revocation list (CRL) for a CA")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "CRL file was imported successfully"),
            @ApiResponse(code = 400, message = "Error while importing CRL file"),
    }
    )
    public Response importCrl(@Context final HttpServletRequest httpServletRequest,
                              @ApiParam(value = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                              @ApiParam("CRL file in DER format") @FormParam("crlFile") final File crlFile,
                              @ApiParam("CRL partition index") @DefaultValue("0") @FormParam("crlPartitionIndex") int crlPartitionIndex
    ) throws AuthorizationDeniedException, RestException {
        return super.importCrl(httpServletRequest, issuerDn, crlFile, crlPartitionIndex);
    }
}
