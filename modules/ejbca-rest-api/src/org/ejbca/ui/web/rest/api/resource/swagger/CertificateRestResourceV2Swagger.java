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

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.Info;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
import org.ejbca.ui.web.rest.api.io.response.CaCertCountResponse;
import org.ejbca.ui.web.rest.api.io.response.CertificateProfileInfoRestResponseV2;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponseV2;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResourceV2;
import org.cesecore.certificates.certificate.InternalCertificateRestSessionLocal;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

/**
 * JAX-RS resource handling Certificate related requests.
 */
@Api(tags = {"v2/certificate"}, value = "Certificate REST Management API")
@Path("v2/certificate")
@SwaggerDefinition(
        /* @Info annotation seems to work properly only when it is configured only once. Must not specify it on any other RestResources in this module! */
        info = @Info(
                title = "EJBCA REST Interface",
                version = BaseRestResource.RESOURCE_VERSION,
                description = "API reference documentation."
        ),
        basePath = "/ejbca/ejbca-rest-api",
        schemes = {Scheme.HTTPS}
)
@Stateless
public class CertificateRestResourceV2Swagger extends CertificateRestResourceV2 {

    @EJB
    private InternalCertificateRestSessionLocal certificateSessionLocal;

    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the status of this REST Resource",
            notes = "Returns status, API version and EJBCA version.",
            response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }

    @GET
    @Path("/count")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get the quantity of rather total issued or active certificates")
    public Response getCertificateCount(@ApiParam(value = "true if an active certificates should be counted only")
                                        @QueryParam("isActive") Boolean isActive) {
        return Response.ok(new CaCertCountResponse(
                certificateSessionLocal.getCertificateCount(isActive)
        )).build();
    }

    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Searches for certificates confirming given criteria and pagination.",
            notes = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchCertificateCriteriaRestRequestV2 model. Use -1 for current_page to get total number of certificate for the request criteria.",
            response = SearchCertificatesRestResponseV2.class
    )
    public Response searchCertificates(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Collection of search criterias and pagination information.") final SearchCertificatesRestRequestV2 searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException, CertificateParsingException {
        return super.searchCertificates(requestContext, searchCertificatesRestRequest);
    }

    @GET
    @Path("/profile/{profile_name}")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Get Certificate Profile Info.",
            response = CertificateProfileInfoRestResponseV2.class)
    public Response getCertificateProfileInfo(
            @Context HttpServletRequest requestContext,
            @PathParam("profile_name") String certProfileName
            ) throws AuthorizationDeniedException, RestException {
        return super.getCertificateProfileInfo(requestContext, certProfileName);
    }

}
