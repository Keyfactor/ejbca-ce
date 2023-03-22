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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.CertificateRequestRestRequest;
import org.ejbca.ui.web.rest.api.io.request.EnrollCertificateRestRequest;
import org.ejbca.ui.web.rest.api.io.request.FinalizeRestRequest;
import org.ejbca.ui.web.rest.api.io.request.KeyStoreRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.response.CertificateRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ExpiringCertificatesRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RevokeStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResource;

import com.keyfactor.CesecoreException;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * JAX-RS resource handling Certificate related requests.
 */
@Api(tags = {"v1/certificate"}, value = "Certificate REST Management API")
@Path("v1/certificate")
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
public class CertificateRestResourceSwagger extends CertificateRestResource {

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

    @POST
    @Path("/pkcs10enroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Enrollment with client generated keys, using CSR subject",
            notes = "Enroll for a certificate given a PEM encoded PKCS#10 CSR.",
            response = CertificateRestResponse.class,
            code = 201)
    public Response enrollPkcs10Certificate(@Context HttpServletRequest requestContext,
                                            final EnrollCertificateRestRequest enrollCertificateRestRequest)
            throws RestException, AuthorizationDeniedException {
        return super.enrollPkcs10Certificate(requestContext, enrollCertificateRestRequest);
    }

    @POST
    @Path("/certificaterequest")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Enrollment with client generated keys for an existing End Entity",
            notes = "Enroll for a certificate given a PEM encoded PKCS#10 CSR.",
            response = CertificateRestResponse.class,
            code = 201)
    public Response certificateRequest(@Context HttpServletRequest requestContext,
                                       final CertificateRequestRestRequest certificateRequestRestRequest)
            throws RestException, AuthorizationDeniedException, CesecoreException, IOException, SignatureException,
            ConstructionException, NoSuchFieldException {
        return super.certificateRequest(requestContext, certificateRequestRestRequest);
    }

    @POST
    @Path("/enrollkeystore")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Keystore enrollment",
            notes = "Creates a keystore for the specified end entity",
            response = CertificateRestResponse.class,
            code = 201)
    public Response enrollKeystore(@Context HttpServletRequest requestContext, KeyStoreRestRequest keyStoreRestRequest)
            throws AuthorizationDeniedException, EjbcaException, KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, IOException, RestException {
        return super.enrollKeystore(requestContext, keyStoreRestRequest);
    }

    @GET
    @Path("/{issuer_dn}/{certificate_serial_number}/revocationstatus")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Checks revocation status of the specified certificate", notes = "Checks revocation status of the specified certificate",
            response = RevokeStatusRestResponse.class)
    public Response revocationStatus(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Subject DN of the issuing CA")
            @PathParam("issuer_dn") String issuerDn,
            @ApiParam(value = "hex serial number (without prefix, e.g. '00')")
            @PathParam("certificate_serial_number") String serialNumber)
            throws AuthorizationDeniedException, RestException, CADoesntExistsException, NotFoundException {
        return super.revocationStatus(requestContext, issuerDn, serialNumber);
    }

    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Revokes the specified certificate",
                  notes = "Revokes the specified certificate or changes revocation reason for an already revoked certificate",
                  response = RevokeStatusRestResponse.class)
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Subject DN of the issuing CA")
            @PathParam("issuer_dn") String issuerDN,
            @ApiParam(value = "hex serial number (without prefix, e.g. '00')")
            @PathParam("certificate_serial_number") String serialNumber,
            @ApiParam(value = "Must be valid RFC5280 reason. One of\n" +
                    " NOT_REVOKED, UNSPECIFIED ,KEY_COMPROMISE,\n" +
                    " CA_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,\n" +
                    " CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE \n\n" +
                    " Only KEY_COMPROMISE is allowed for new revocation reason if revocation reason is to be changed.")
            @QueryParam("reason") String reason,
            @ApiParam(value = "ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'")
            @QueryParam("date") String date,
            @ApiParam(value = "ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'")
            @QueryParam("invalidity_date") String invalidityDate)

            throws AuthorizationDeniedException, RestException, ApprovalException, RevokeBackDateNotAllowedForProfileException,
            CADoesntExistsException, AlreadyRevokedException, NoSuchEndEntityException, CertificateProfileDoesNotExistException, 
            WaitingForApprovalException {
        return super.revokeCertificate(requestContext, issuerDN, serialNumber, reason, date, invalidityDate);
    }

    @GET
    @Path("/expire")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get a list of certificates that are about to expire",
            notes = "List of certificates expiring within specified number of days",
            response = ExpiringCertificatesRestResponse.class)
    public Response getCertificatesAboutToExpire(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Request certificates expiring within this number of days")
            @QueryParam("days") long days,
            @ApiParam(value = "Next offset to display results of, if maxNumberOfResults is exceeded. Starts from 0.")
            @QueryParam("offset") int offset,
            @ApiParam(value = "Maximum number of certificates to display. If result exceeds this value. Modify 'offset' to retrieve more results")
            @QueryParam("maxNumberOfResults") int maxNumberOfResults)
            throws AuthorizationDeniedException, CertificateEncodingException, RestException {
        return super.getCertificatesAboutToExpire(requestContext, days, offset, maxNumberOfResults);
    }

    @POST
    @Path("/{request_id}/finalize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Finalize enrollment",
            notes = "Finalizes enrollment after administrator approval using request Id",
            response = CertificateRestResponse.class,
            code = 201)
    public Response finalizeEnrollment(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Approval request id")
            @PathParam("request_id") int requestId,
            @ApiParam(value = "responseFormat must be one of 'P12', 'BCFKS', 'JKS', 'DER'") FinalizeRestRequest request)
            throws AuthorizationDeniedException, RestException, EjbcaException, WaitingForApprovalException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return super.finalizeEnrollment(requestContext, requestId, request);
    }

    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Searches for certificates confirming given criteria.",
            notes = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchCertificateCriteriaRestRequest model.",
            response = SearchCertificatesRestResponse.class
    )
    public Response searchCertificates(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Maximum number of results and collection of search criterias.") final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException {
        return super.searchCertificates(requestContext, searchCertificatesRestRequest);
    }
}
