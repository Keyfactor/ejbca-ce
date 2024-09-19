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

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.media.ArraySchema;
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
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.*;
import org.ejbca.ui.web.rest.api.io.response.CertificateRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CertificateEnrollmentRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ExpiringCertificatesRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RevokeStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;
import org.ejbca.ui.web.rest.api.resource.BaseRestResource;
import org.ejbca.ui.web.rest.api.resource.CertificateRestResource;

import com.keyfactor.CesecoreException;


/**
 * JAX-RS resource handling Certificate related requests.
 */
@Tag(name = "v1/certificate", description = "Certificate REST Management API")
@Path("v1/certificate")
@OpenAPIDefinition(
        /* @Info annotation seems to work properly only when it is configured only once. Must not specify it on any other RestResources in this module! */
        info = @Info(
                title = "EJBCA REST Interface",
                version = BaseRestResource.RESOURCE_VERSION,
                description = "API reference documentation."
        ),
        servers = @Server(
                url = "/ejbca/ejbca-rest-api",
                description = "HTTPS Server"
        )
)
@Stateless
public class CertificateRestResourceSwagger extends CertificateRestResource {

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

    @POST
    @Path("/pkcs10enroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Enrollment with client generated keys, using CSR subject.",
            description = "Enroll for a certificate given a PEM encoded PKCS#10 CSR. "
                    + "\nResponse Format is 'DER' (default when excluded) or 'PKCS7' in base64 encoded PEM format",
            responses = {
                    @ApiResponse(responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CertificateEnrollmentRestResponse.class))
                    )
            })
    public Response enrollPkcs10Certificate(@Context HttpServletRequest requestContext,
                                            final EnrollCertificateRestRequest enrollCertificateRestRequest)
            throws RestException, AuthorizationDeniedException {
        return super.enrollPkcs10Certificate(requestContext, enrollCertificateRestRequest);
    }

    @POST
    @Path("/certificaterequest")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Enrollment with client generated keys for an existing End Entity",
            description = "Enroll for a certificate given a PEM encoded PKCS#10 CSR.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CertificateEnrollmentRestResponse.class))
                    )
            })
    public Response certificateRequest(@Context HttpServletRequest requestContext,
                                       final CertificateRequestRestRequest certificateRequestRestRequest)
            throws RestException, AuthorizationDeniedException, CesecoreException, IOException,
            SignatureException, NoSuchFieldException {
        return super.certificateRequest(requestContext, certificateRequestRestRequest);
    }

    @POST
    @Path("/enrollkeystore")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Keystore enrollment",
            description = "Creates a keystore for the specified end entity",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CertificateEnrollmentRestResponse.class))
                    )
            })
    public Response enrollKeystore(@Context HttpServletRequest requestContext, KeyStoreRestRequest keyStoreRestRequest)
            throws AuthorizationDeniedException, EjbcaException, KeyStoreException, NoSuchProviderException,
            NoSuchAlgorithmException, CertificateException, IOException, RestException, CADoesntExistsException,
            UnrecoverableKeyException {
        return super.enrollKeystore(requestContext, keyStoreRestRequest);
    }

    @GET
    @Path("/{issuer_dn}/{certificate_serial_number}/revocationstatus")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Checks revocation status of the specified certificate", description = "Checks revocation status of the specified certificate",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = RevokeStatusRestResponse.class))
                    )
            })
    public Response revocationStatus(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Subject DN of the issuing CA")
            @PathParam("issuer_dn") String issuerDn,
            @Parameter(description = "hex serial number (without prefix, e.g. '00')")
            @PathParam("certificate_serial_number") String serialNumber)
            throws AuthorizationDeniedException, RestException, CADoesntExistsException, NotFoundException {
        return super.revocationStatus(requestContext, issuerDn, serialNumber);
    }

    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Revokes the specified certificate",
            description = "Revokes the specified certificate, changes revocation reason for an already revoked certificate, sets invalidity or revocation date",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = RevokeStatusRestResponse.class))
                    )
            })
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Subject DN of the issuing CA")
            @PathParam("issuer_dn") String issuerDN,
            @Parameter(description = "Hex serial number (without prefix, e.g. '00')")
            @PathParam("certificate_serial_number") String serialNumber,
            @Parameter(description = "Valid RFC5280 reason. One of\n" +
                    " NOT_REVOKED, UNSPECIFIED ,KEY_COMPROMISE,\n" +
                    " CA_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,\n" +
                    " CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE \n\n" +
                    " Only KEY_COMPROMISE is allowed for new revocation reason if revocation reason is to be changed.")
            @QueryParam("reason") String reason,
            @Parameter(description = "ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'")
            @QueryParam("date") String date,
            @Parameter(description = "ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'. Will be ignored with revocation reason REMOVE_FROM_CRL")
            @QueryParam("invalidity_date") String invalidityDate)

            throws AuthorizationDeniedException, RestException, ApprovalException, RevokeBackDateNotAllowedForProfileException,
            CADoesntExistsException, AlreadyRevokedException, NoSuchEndEntityException, CertificateProfileDoesNotExistException,
            WaitingForApprovalException {
        return super.revokeCertificate(requestContext, issuerDN, serialNumber, reason, date, invalidityDate);
    }

    @GET
    @Path("/expire")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Get a list of certificates that are about to expire",
            description = "List of certificates expiring within specified number of days",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = ExpiringCertificatesRestResponse.class))
                    )
            })
    public Response getCertificatesAboutToExpire(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Request certificates expiring within this number of days")
            @QueryParam("days") long days,
            @Parameter(description = "Next offset to display results of, if maxNumberOfResults is exceeded. Starts from 0.")
            @QueryParam("offset") int offset,
            @Parameter(description = "Maximum number of certificates to display. If result exceeds this value. Modify 'offset' to retrieve more results")
            @QueryParam("maxNumberOfResults") int maxNumberOfResults)
            throws AuthorizationDeniedException, CertificateEncodingException, RestException {
        return super.getCertificatesAboutToExpire(requestContext, days, offset, maxNumberOfResults);
    }

    @POST
    @Path("/{request_id}/finalize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Finalize enrollment",
            description = "Finalizes enrollment after administrator approval using request Id",
            responses = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "Successful operation",
                            content = @Content(schema = @Schema(implementation = CertificateRestResponse.class))
                    )
            })
    public Response finalizeEnrollment(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Approval request id")
            @PathParam("request_id") int requestId,
            @Parameter(description = "responseFormat must be one of 'P12', 'BCFKS', 'JKS', 'DER'") FinalizeRestRequest request)
            throws AuthorizationDeniedException, RestException, EjbcaException, WaitingForApprovalException,
            KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        return super.finalizeEnrollment(requestContext, requestId, request);
    }

    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Searches for certificates confirming given criteria.",
            description = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchCertificateCriteriaRestRequest model.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successful operation",
                            content = @Content(array = @ArraySchema(schema = @Schema(implementation = SearchCertificatesRestResponse.class)))
                    )
            })
    public Response searchCertificates(
            @Context HttpServletRequest requestContext,
            @Parameter(description = "Maximum number of results and collection of search criterias.") final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException {
        return super.searchCertificates(requestContext, searchCertificatesRestRequest);
    }
}
