/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.resource;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
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
import javax.ws.rs.core.Response.Status;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.TokenDownloadType;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaCertificateSearchRequest;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.EnrollCertificateRestRequest;
import org.ejbca.ui.web.rest.api.io.request.FinalizeRestRequest;
import org.ejbca.ui.web.rest.api.io.request.KeyStoreRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.response.CertificateRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CertificatesRestResponse;
import org.ejbca.ui.web.rest.api.io.response.ExpiringCertificatesRestResponse;
import org.ejbca.ui.web.rest.api.io.response.PaginationRestResponseComponent;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RevokeStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.Info;
import io.swagger.annotations.SwaggerDefinition;
import io.swagger.annotations.SwaggerDefinition.Scheme;

/**
 * JAX-RS resource handling certificate-related requests.
 *
 * @version $Id$
 */
@Api(tags = {"v1/certificate"}, value = "Certificate REST Management API")
@SwaggerDefinition(
    /* @Info annotation seems to work properly only when it is configured only once. Must not specify it on any other RestResources in this module! */
    info = @Info(
        title = "EJBCA REST Interface",
        version = BaseRestResource.RESOURCE_VERSION,
        description = "API reference documentation."
    ),
    basePath="/ejbca/ejbca-rest-api",
    schemes={Scheme.HTTPS}
)
@Path("v1/certificate")
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateRestResource extends BaseRestResource {

    /**
     * Internal localization of logs and errors
     */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final Logger log = Logger.getLogger(CertificateRestResource.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;

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
    @ApiOperation(value = "Enrollment by PKCS10 request",
                  notes = "Enroll certificate given PKCS10 CSR.\nGiven CSR must be base64 encoded PEM format", 
                  response = CertificateRestResponse.class, code = 201)
    public Response enrollPkcs10Certificate(@Context HttpServletRequest requestContext, EnrollCertificateRestRequest enrollCertificateRestRequest)
            throws RestException, AuthorizationDeniedException {
        try {
            AuthenticationToken authenticationToken = getAdmin(requestContext, false);
            byte[] certificate = raMasterApi.createCertificateRest(
                    authenticationToken,
                    EnrollCertificateRestRequest.converter().toEnrollPkcs10CertificateRequest(enrollCertificateRestRequest)
            );
            X509Certificate cert = CertTools.getCertfromByteArray(certificate, X509Certificate.class);
            CertificateRestResponse enrollCertificateRestResponse = CertificateRestResponse.converter().toRestResponse(cert);
            return Response.status(Status.CREATED).entity(enrollCertificateRestResponse).build();
        } catch (EjbcaException | CertificateException | EndEntityProfileValidationException | CesecoreException e) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), e.getMessage());
        }
    }

    @POST
    @Path("/enrollkeystore")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Keystore enrollment",
        notes = "Creates a keystore for the specified end entity",
        response = CertificateRestResponse.class,
        code = 201)
    public Response enrollKeystore(
            @Context HttpServletRequest requestContext,
            KeyStoreRestRequest keyStoreRestRequest)
                    throws AuthorizationDeniedException, EjbcaException, KeyStoreException, NoSuchProviderException,
                        NoSuchAlgorithmException, CertificateException, IOException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        EndEntityInformation endEntityInformation = raMasterApi.searchUser(admin, keyStoreRestRequest.getUsername());
        if (endEntityInformation == null) {
            throw new NotFoundException("The end entity '" + keyStoreRestRequest.getUsername() + "' does not exist");
        }
        if (!AlgorithmTools.getAvailableKeyAlgorithms().contains(keyStoreRestRequest.getKeyAlg())) {
            throw new RestException(422, "Unsupported key algorithm '" + keyStoreRestRequest.getKeyAlg() + "'");
        }
        try {
            KeyTools.checkValidKeyLength(keyStoreRestRequest.getKeySpec());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RestException(422, e.getMessage());
        }
        endEntityInformation.setPassword(keyStoreRestRequest.getPassword());
        endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmType(keyStoreRestRequest.getKeyAlg());
        endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmSubType(keyStoreRestRequest.getKeySpec());
        final int tokenType = endEntityInformation.getTokenType();
        if (!(tokenType == SecConst.TOKEN_SOFT_P12 || tokenType == SecConst.TOKEN_SOFT_JKS)) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Unsupported token type. Must be PKCS12 or JKS");
        }
        final byte[] keyStoreBytes = raMasterApi.generateKeyStore(admin, endEntityInformation);
        final KeyStore keyStore = KeyTools.createKeyStore(keyStoreBytes, keyStoreRestRequest.getPassword());
        CertificateRestResponse response = CertificateRestResponse.converter().toRestResponse(keyStore, keyStoreRestRequest.getPassword());
        return Response.status(Status.CREATED).entity(response).build();
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
            @PathParam("certificate_serial_number") String serialNumber) throws AuthorizationDeniedException, RestException, CADoesntExistsException, NotFoundException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        final BigInteger serialNr;
        final CertificateStatus status;
        try {
            serialNr = StringTools.getBigIntegerFromHexString(serialNumber);
            status = raMasterApi.getCertificateStatus(admin, issuerDn, serialNr);
        } catch (NumberFormatException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid serial number format. Should be "
                    + "HEX encoded (optionally with '0x' prefix) e.g. '0x10782a83eef170d4'");
        } catch (CADoesntExistsException e) {
            // Returning an ID which doesn't exist makes no sense, replace with SDN.
            throw new CADoesntExistsException("CA '" + issuerDn + "' does not exist.");
        }
        if (status == null || status.equals(CertificateStatus.NOT_AVAILABLE)) {
            throw new NotFoundException("Certificate with serial number '" + serialNumber + "' and issuer DN '" + issuerDn + "' was not found");
        }
        return Response.ok(RevokeStatusRestResponse.converter().toRestResponse(status, issuerDn, serialNumber)).build();
    }

    /**
     * Revokes the specified certificate
     *
     * @param requestContext HttpServletRequest
     * @param issuerDN       of the certificate to revoke
     * @param serialNumber   HEX encoded SN with or without 0x prefix
     * @param reason         revocation reason. Must be valid RFC5280 reason:
     *                          NOT_REVOKED, UNSPECIFIED , KEY_COMPROMISE,
     *                          CA_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,
     *                          CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE
     * @param date           revocation date (optional). Must be valid ISO8601 date string
     * @return JSON representation of serialNr, issuerDn, revocation status, date and optional message.
     */
    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Revokes the specified certificate", notes = "Revokes the specified certificate", response = RevokeStatusRestResponse.class)
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Subject DN of the issuing CA")
            @PathParam("issuer_dn") String issuerDN,
            @ApiParam(value = "hex serial number (without prefix, e.g. '00')")
            @PathParam("certificate_serial_number") String serialNumber,
            @ApiParam(value = "Must be valid RFC5280 reason. One of\n" + 
                    " NOT_REVOKED, UNSPECIFIED ,KEY_COMPROMISE,\n" + 
                    " CA_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION,\n" + 
                    " CERTIFICATE_HOLD, REMOVE_FROM_CRL, PRIVILEGES_WITHDRAWN, AA_COMPROMISE")
            @QueryParam("reason") String reason,
            @ApiParam(value = "ISO 8601 Date string, eg. '2018-06-15T14:07:09Z'")
            @QueryParam("date") String date)
            throws AuthorizationDeniedException, RestException, ApprovalException, RevokeBackDateNotAllowedForProfileException, CADoesntExistsException, AlreadyRevokedException,
            NoSuchEndEntityException, WaitingForApprovalException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        RevocationReasons reasons = RevocationReasons.getFromCliValue(reason);
        // TODO Replace with @ValidRevocationReason
        if (reasons == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid revocation reason.");
        }
        final int revocationReason = reasons.getDatabaseValue();
        final BigInteger serialNr;
        try {
            serialNr = StringTools.getBigIntegerFromHexString(serialNumber);
        } catch (NumberFormatException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid serial number format. Should be "
                    + "HEX encoded (optionally with '0x' prefix) e.g. '0x10782a83eef170d4'");
        }
        Date revocationDate;
        if (date != null) {
            revocationDate = getValidatedRevocationDate(date);
        } else {
            revocationDate = new Date();
        }
        raMasterApi.revokeCert(admin, serialNr, revocationDate, issuerDN, revocationReason, false);
        
        final RevokeStatusRestResponse result = RevokeStatusRestResponse.builder().
            serialNumber(serialNumber).
            issuerDn(issuerDN).
            revocationDate(revocationDate).
            revoked(true).
            revocationReason(reason).
            message("Successfully revoked").
            build();
        return Response.ok(result).build();
    }

    // TODO Replace with @ValidRevocationDate annotation
    private Date getValidatedRevocationDate(String sDate) throws RestException {
        Date date = null;
        if (sDate != null) {
            try {
                date = DatatypeConverter.parseDateTime(sDate).getTime();
            } catch (IllegalArgumentException e) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), intres.getLocalizedMessage("ra.bad.date", sDate));
            }
            if (date.after(new Date())) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Revocation date in the future: '" + sDate + "'.");
            }
        }
        return date;
    }

    @GET
    @Path("/expire")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Get a list of certificates that are about to expire",
        notes = "List of certificates expiring within specified number of days",
        response = ExpiringCertificatesRestResponse.class)
    public Response getCertificatesAboutToExpire(@Context HttpServletRequest requestContext,
            @ApiParam(value = "Request certificates expiring within this number of days")
            @QueryParam("days") long days,
            @ApiParam(value = "Next offset to display results of, if maxNumberOfResults is exceeded. Starts from 0.")
            @QueryParam("offset") int offset,
            @ApiParam(value = "Maximum number of certificates to display. If result exceeds this value. Modify 'offset' to retrieve more results")
            @QueryParam("maxNumberOfResults") int maxNumberOfResults) throws AuthorizationDeniedException, CertificateEncodingException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, true);
        int count = raMasterApi.getCountOfCertificatesByExpirationTime(admin, days);
        final Collection<Certificate> expiringCertificates = EJBTools
                .unwrapCertCollection(raMasterApi.getCertificatesByExpirationTime(admin, days, maxNumberOfResults, offset));
        int processedResults = offset + maxNumberOfResults;
        PaginationRestResponseComponent paginationRestResponseComponent = PaginationRestResponseComponent.builder().setMoreResults(count > processedResults)
                .setNextOffset(offset + maxNumberOfResults)
                .setNumberOfResults(count - processedResults)
                .build();
        CertificatesRestResponse certificatesRestResponse = new CertificatesRestResponse(
                CertificatesRestResponse.converter().toRestResponses(new ArrayList<Certificate>(expiringCertificates)));
        ExpiringCertificatesRestResponse response = new ExpiringCertificatesRestResponse(paginationRestResponseComponent, certificatesRestResponse);
        return Response.ok(response).build();
    }

    @POST
    @Path("/{request_id}/finalize")
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(value = "Finalize enrollment",
        notes = "Finalizes enrollment after administrator approval using request Id",
        response = CertificateRestResponse.class,
        code = 201)
    public Response finalizeEnrollment(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Approval request id") @PathParam("request_id") int requestId,
            @ApiParam(value = "responseFormat must be one of 'P12', 'JKS', 'DER'") FinalizeRestRequest request)
                    throws AuthorizationDeniedException, RestException, EjbcaException, WaitingForApprovalException,
                        KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        final RaApprovalRequestInfo approvalRequestInfo = raMasterApi.getApprovalRequest(admin, requestId);
        final String password = request.getPassword();
        final String responseFormat = request.getResponseFormat();
        if (approvalRequestInfo == null) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Could not find request with Id '" + requestId + "'");
        }
        if (TokenDownloadType.getIdFromName(responseFormat) == null) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Invalid parameter: response_format");
        }

        final ApprovalRequest approvalRequest = approvalRequestInfo.getApprovalData().getApprovalRequest();
        String requestUsername = approvalRequestInfo.getEditableData().getUsername();
        EndEntityInformation endEntityInformation;
        final int requestStatus = approvalRequestInfo.getStatus();
        switch (requestStatus) {
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                throw new WaitingForApprovalException("Request with Id '" + requestId + "' is still waiting for approval", requestId);
            case ApprovalDataVO.STATUS_REJECTED:
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Request with Id '" + requestId + "' has been rejected");
            case ApprovalDataVO.STATUS_EXPIRED:
            case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Request with Id '" + requestId + "' has expired");
            case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Request with Id '" + requestId + "' could not be executed");
            case ApprovalDataVO.STATUS_APPROVED:
            case ApprovalDataVO.STATUS_EXECUTED:
                if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
                    KeyRecoveryApprovalRequest keyRecoveryApprovalRequest = (KeyRecoveryApprovalRequest) approvalRequest;
                    requestUsername = keyRecoveryApprovalRequest.getUsername();
                }
                endEntityInformation = raMasterApi.searchUser(admin, requestUsername);
                if (endEntityInformation == null) {
                    log.error("Could not find endEntity for the username '" + requestUsername + "'");
                    throw new NotFoundException("The end entity '" + requestUsername + "' does not exist");
                } else if (endEntityInformation.getStatus() == EndEntityConstants.STATUS_GENERATED) {
                    throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Enrollment with Id '" + requestId + "' has already been finalized");
                }
                break;
            default:
                throw new IllegalStateException("The status of request with Id '" + requestId + "' is unknown");
        }

        final CertificateRestResponse response;
        endEntityInformation.setPassword(password);
        // Initial request was a CSR
        if (endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN) {
            if (!(responseFormat.equals(TokenDownloadType.DER.name()) || responseFormat.equals(TokenDownloadType.PEM.name()))) {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Invalid response format. Cannot create keystore for certificate request "
                        + " with user generated keys");
            }
            byte[] certificateBytes = raMasterApi.createCertificate(admin, endEntityInformation); // X509Certificate
            X509Certificate certificate = CertTools.getCertfromByteArray(certificateBytes, X509Certificate.class);
            if (responseFormat.equals(TokenDownloadType.PEM.name())) {
                byte[] pemBytes = CertTools.getPemFromCertificateChain(Collections.singletonList((Certificate) certificate));
                response = CertificateRestResponse.builder().setCertificate(pemBytes).
                        setSerialNumber(CertTools.getSerialNumberAsString(certificate)).setResponseFormat("PEM").build();
            } else {
                // DER encoding
                response = CertificateRestResponse.converter().toRestResponse(certificate);
            }
        } else {
            // Initial request was server generated key store
            byte[] certificateBytes;
            if (responseFormat.equals(TokenDownloadType.JKS.name())) {
                endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_JKS);
            } else if (responseFormat.equals(TokenDownloadType.P12.name())) {
                endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
            } else if (responseFormat.equals(TokenDownloadType.PEM.name())) {
                endEntityInformation.setTokenType(EndEntityConstants.TOKEN_SOFT_PEM);
            } else {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Invalid response format. Must be 'JKS', 'P12' or 'PEM'");
            }

            certificateBytes = raMasterApi.generateKeyStore(admin, endEntityInformation);
            if (responseFormat.equals(TokenDownloadType.PEM.name())) {
                X509Certificate certificate = CertTools.getCertfromByteArray(certificateBytes, X509Certificate.class);
                response = CertificateRestResponse.builder().setCertificate(certificateBytes).
                        setSerialNumber(CertTools.getSerialNumberAsString(certificate)).setResponseFormat("PEM").build();
            } else if (responseFormat.equals(TokenDownloadType.DER.name())) {
                final X509Certificate x509Certificate = CertTools.getCertfromByteArray(certificateBytes, X509Certificate.class);
                response = CertificateRestResponse.converter().toRestResponse(x509Certificate);
            } else {
                // JKS or PKCS12. Will be detected by content.
                final KeyStore keyStore = KeyTools.createKeyStore(certificateBytes, password);
                response = CertificateRestResponse.converter().toRestResponse(keyStore, password);
            }
        }
        return Response.status(Status.CREATED).entity(response).build();
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
        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);
        validateObject(searchCertificatesRestRequest);
        authorizeSearchCertificatesRestRequestReferences(authenticationToken, searchCertificatesRestRequest);
        final SearchCertificatesRestResponse searchCertificatesRestResponse = searchCertificates(authenticationToken, searchCertificatesRestRequest);
        return Response.ok(searchCertificatesRestResponse).build();
    }
    
    /**
     * Authorizes the input search request for proper access references (End entity profile ids, Certificate profile ids and CA ids) inside a request.
     *
     * @param authenticationToken authentication token to use.
     * @param searchCertificatesRestRequest input search request.
     * @throws RestException In case of inaccessible reference usage.
     */
    private void authorizeSearchCertificatesRestRequestReferences(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws RestException {
        Map<Integer, String> availableEndEntityProfiles = new HashMap<>();
        Map<Integer, String> availableCertificateProfiles = new HashMap<>();
        Map<Integer, String> availableCAs = new HashMap<>();
        for(SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : searchCertificatesRestRequest.getCriteria()) {
            final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
            if(criteriaProperty == null) {
                throw new RestException(
                        Response.Status.BAD_REQUEST.getStatusCode(),
                        "Invalid search criteria content."
                );
            }
            switch (criteriaProperty) {
                case END_ENTITY_PROFILE:
                    availableEndEntityProfiles = loadAuthorizedEndEntityProfiles(authenticationToken, availableEndEntityProfiles);
                    final String criteriaEndEntityProfileName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaEndEntityProfileId = getKeyFromMapByValue(availableEndEntityProfiles, criteriaEndEntityProfileName);
                    if(criteriaEndEntityProfileId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown end entity profile."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaEndEntityProfileId);
                    break;
                case CERTIFICATE_PROFILE:
                    availableCertificateProfiles = loadAuthorizedCertificateProfiles(authenticationToken, availableCertificateProfiles);
                    final String criteriaCertificateProfileName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaCertificateProfileId = getKeyFromMapByValue(availableCertificateProfiles, criteriaCertificateProfileName);
                    if(criteriaCertificateProfileId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown certificate profile."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaCertificateProfileId);
                    break;
                case CA:
                    availableCAs = loadAuthorizedCAs(authenticationToken, availableCAs);
                    final String criteriaCAName = searchCertificateCriteriaRestRequest.getValue();
                    final Integer criteriaCAId = getKeyFromMapByValue(availableCAs, criteriaCAName);
                    if(criteriaCAId == null) {
                        throw new RestException(
                                Response.Status.BAD_REQUEST.getStatusCode(),
                                "Invalid search criteria content, unknown CA."
                        );
                    }
                    searchCertificateCriteriaRestRequest.setIdentifier(criteriaCAId);
                    break;
                default:
                    // Do nothing
            }
        }
    }
    
    /**
     * Searches for certificates within given criteria.
     *
     * @param authenticationToken authentication token to use.
     * @param searchCertificatesRestRequest search criteria.
     * @return Search results.
     * @throws RestException In case of malformed criteria.
     * @throws CertificateEncodingException In case of failure in certificate reading.
     */
    private SearchCertificatesRestResponse searchCertificates(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequest searchCertificatesRestRequest
    ) throws RestException, CertificateEncodingException {
        final RaCertificateSearchRequest raCertificateSearchRequest = SearchCertificatesRestRequest.converter().toEntity(searchCertificatesRestRequest);
        final RaCertificateSearchResponse raCertificateSearchResponse = raMasterApi.searchForCertificates(authenticationToken, raCertificateSearchRequest);
        return SearchCertificatesRestResponse.converter().toRestResponse(raCertificateSearchResponse);
    }

    private Map<Integer, String> loadAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableEndEntityProfiles) {
        if(availableEndEntityProfiles.isEmpty()) {
            return raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken);
        }
        return availableEndEntityProfiles;
    }

    private Map<Integer, String> loadAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken, final  Map<Integer, String> availableCertificateProfiles) {
        if(availableCertificateProfiles.isEmpty()) {
            return raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken);
        }
        return availableCertificateProfiles;
    }

    private Map<Integer, String> loadAuthorizedCAs(final AuthenticationToken authenticationToken, final Map<Integer, String> availableCAs) {
        if(availableCAs.isEmpty()) {
            final Map<Integer, String> authorizedCAIds = new HashMap<>();
            final List<CAInfo> caInfosList = raMasterApi.getAuthorizedCas(authenticationToken);
            for(final CAInfo caInfo : caInfosList) {
                authorizedCAIds.put(caInfo.getCAId(), caInfo.getName());
            }
            return authorizedCAIds;
        }
        return availableCAs;
    }

    private Integer getKeyFromMapByValue(final Map<Integer, String> map, final String value) {
        for(Integer key : map.keySet()) {
            if(map.get(key).equals(value)) {
                return key;
            }
        }
        return null;
    }
}
