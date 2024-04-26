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
package org.ejbca.ui.web.rest.api.resource;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateDataSessionLocal;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaCertificateProfileResponseV2;
import org.ejbca.core.model.era.RaCertificateSearchRequestV2;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
import org.ejbca.ui.web.rest.api.io.response.CertificateCountResponse;
import org.ejbca.ui.web.rest.api.io.response.CertificateProfileInfoRestResponseV2;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponseV2;

/**
 * JAX-RS resource handling certificate-related requests version 2.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateRestResourceV2 extends BaseRestResource {

    private static final String RESOURCE_STATUS = "OK";
    protected static final String RESOURCE_VERSION = "2.0";

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    private static final Logger log = Logger.getLogger(CertificateRestResourceV2.class);
    
    @EJB
    private CertificateDataSessionLocal certDataSession;
    
    @Override
    public Response status() {
        return Response.ok(RestResourceStatusRestResponse.builder()
                .status(RESOURCE_STATUS)
                .version(RESOURCE_VERSION)
                .revision(GlobalConfiguration.EJBCA_VERSION)
                .build()
        ).build();
    }

    public Response getCertificateCount(HttpServletRequest requestContext, Boolean isActive) throws AuthorizationDeniedException, RestException {
        AuthenticationToken admin = getAdmin(requestContext, false);
        return Response.ok(new CertificateCountResponse(
                certDataSession.getCertificateCount(admin, isActive)
        )).build();
    }

    /**
     * Searches for certificates within given criteria
     * @param requestContext the HTTP request context
     * @param searchCertificatesRestRequest the REST request
     * @return HTTP Response containing search results or error response
     * @throws AuthorizationDeniedException
     * @throws RestException
     * @throws CertificateEncodingException
     * @throws CertificateParsingException
     */
    public Response searchCertificates(
            final HttpServletRequest requestContext,
            @Valid final SearchCertificatesRestRequestV2 searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException, CertificateParsingException {
        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);

        Map<Integer, String> availableEndEntityProfiles = 
                CertificateRestResourceUtil.loadAuthorizedEndEntityProfiles(authenticationToken, raMasterApi);
        Map<Integer, String> availableCertificateProfiles = 
                CertificateRestResourceUtil.loadAuthorizedCertificateProfiles(authenticationToken, raMasterApi);
        Map<Integer, String> availableCAs = 
                CertificateRestResourceUtil.loadAuthorizedCAs(authenticationToken, raMasterApi);
        CertificateRestResourceUtil.authorizeSearchCertificatesRestRequestReferences(
                authenticationToken, raMasterApi, searchCertificatesRestRequest, 
                availableEndEntityProfiles, availableCertificateProfiles, availableCAs);
        final RaCertificateSearchRequestV2 raRequest = SearchCertificatesRestRequestV2.converter().toEntity(searchCertificatesRestRequest);
        final RaCertificateSearchResponseV2 raResponse = raMasterApi.searchForCertificatesV2(authenticationToken, raRequest);
        if (raResponse.getStatus() == RaCertificateSearchResponseV2.Status.TIMEOUT
                || raResponse.getStatus() == RaCertificateSearchResponseV2.Status.ERROR) {
                log.info("At least one certificate search database query timed out, responding with HTTP 500 error code.");
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
        final SearchCertificatesRestResponseV2 restResponse = SearchCertificatesRestResponseV2.converter().toRestResponse(raResponse,
                searchCertificatesRestRequest.getPagination(), availableEndEntityProfiles, availableCertificateProfiles);
        return Response.ok(restResponse).build();
    }
    
    /**
     * Get Certificate Profile Info
     * 
     * @param requestContext 
     * @param profileName is the name of the Certificate Profile
     * @return response containing Certificate Profile Info
     * @throws AuthorizationDeniedException
     * @throws RestException In case of malformed criteria.
     */
    public Response getCertificateProfileInfo(final HttpServletRequest requestContext, final String profileName
            ) throws AuthorizationDeniedException, RestException  {
        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);
        final CertificateProfileInfoRestResponseV2 getCertificateProfileInfoRestResponse = getCertificateProfileInfo(authenticationToken, profileName);
        return Response.ok(getCertificateProfileInfoRestResponse).build();
    }
 
    
    /**
     * Mark the certificate with serialNumber and issuerDN for recovery
     * 
     * @param requestContext
     * @param certificateSerialNumber
     * @param issuerDN
     * @return
     * @throws AuthorizationDeniedException
     * @throws RestException
     * @throws CADoesntExistsException
     * @throws EjbcaException
     * @throws WaitingForApprovalException
     */
    public Response markCertificateForKeyRecovery(final HttpServletRequest requestContext, final String certificateSerialNumber,
            final String issuerDN)
            throws AuthorizationDeniedException, RestException, CADoesntExistsException, EjbcaException, WaitingForApprovalException {

        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);

        String certDecimalSerialNumber = StringUtils.EMPTY;
        try {
            certDecimalSerialNumber = new BigInteger(certificateSerialNumber, 16).toString();
        } catch (NumberFormatException ex) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid certificate serial number is provided in the reques.");
        }

        // Finding username from db first, as it is needed by key recovery code flow.
        String userName;

        try {
            userName = raMasterApi.findUsernameByIssuerDnAndSerialNumber(issuerDN, certDecimalSerialNumber);
        } catch (Exception ex) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    "No username found for the combination of the issuer dn and certificate serial number.");
        }
        // Using same logic as in the web service code.
        raMasterApi.keyRecoverWS(authenticationToken, userName, certificateSerialNumber, issuerDN);

        return Response.ok().build();
    }
    
    /**
     * Get Certificate Profile Info
     * 
     * @param authenticationToken
     * @param profileName is the name of the Certificate Profile
     * @return a CertificateProfileInfoRestResponseV2 containing Certificate Profile Info
     * @throws RestException In case of malformed criteria.
     */
    private CertificateProfileInfoRestResponseV2 getCertificateProfileInfo(final AuthenticationToken authenticationToken, final String profileName)
            throws RestException {
        RaCertificateProfileResponseV2 raResponse = raMasterApi.getCertificateProfileInfo(authenticationToken, profileName);
        if (raResponse == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid search criteria, unknown certificate profile.");
        }
        return new CertificateProfileInfoRestResponseV2().convert().toCertificateProfileInfoRestResponse(raResponse);
    }
}
