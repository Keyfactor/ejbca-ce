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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaCertificateSearchRequestV2;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
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
    @EJB
    private CaSessionLocal caSession;

    @Override
    public Response status() {
        return Response.ok(RestResourceStatusRestResponse.builder()
                .status(RESOURCE_STATUS)
                .version(RESOURCE_VERSION)
                .revision(GlobalConfiguration.EJBCA_VERSION)
                .build()
        ).build();
    }

    public Response searchCertificates(
            final HttpServletRequest requestContext,
            final SearchCertificatesRestRequestV2 searchCertificatesRestRequest
    ) throws AuthorizationDeniedException, RestException, CertificateEncodingException, CertificateParsingException {
        final AuthenticationToken authenticationToken = getAdmin(requestContext, true);
        validateObject(searchCertificatesRestRequest);
        CertificateRestResourceUtil.authorizeSearchCertificatesRestRequestReferences(authenticationToken, raMasterApi, searchCertificatesRestRequest);
        final SearchCertificatesRestResponseV2 searchCertificatesRestResponse = searchCertificates(authenticationToken, searchCertificatesRestRequest);
        return Response.ok(searchCertificatesRestResponse).build();
    }

    /**
     * Searches for certificates within given criteria.
     *
     * @param authenticationToken authentication token to use.
     * @param restRequest         search criteria.
     * @return Search results.
     * @throws RestException                In case of malformed criteria.
     * @throws CertificateEncodingException In case of failure in certificate reading.
     * @throws CertificateParsingException  if the certificate from Base64CertData cannot be parsed.
     */
    private SearchCertificatesRestResponseV2 searchCertificates(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequestV2 restRequest
    ) throws RestException, CertificateEncodingException, CertificateParsingException {
        final RaCertificateSearchRequestV2 raRequest = SearchCertificatesRestRequestV2.converter().toEntity(restRequest);
        final RaCertificateSearchResponseV2 raResponse = (RaCertificateSearchResponseV2) raMasterApi.searchForCertificatesV2(authenticationToken, raRequest);
        return SearchCertificatesRestResponseV2.converter().toRestResponse(raResponse, restRequest.getPagination());
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
     * Get Certificate Profile Info
     * 
     * @param authenticationToken
     * @param profileName is the name of the Certificate Profile
     * @return a CertificateProfileInfoRestResponseV2 containing Certificate Profile Info
     * @throws AuthorizationDeniedException
     * @throws RestException In case of malformed criteria.
     */
    private CertificateProfileInfoRestResponseV2 getCertificateProfileInfo(final AuthenticationToken authenticationToken, final String profileName) throws AuthorizationDeniedException, RestException {
        IdNameHashMap<CertificateProfile> availableCertificateProfilesNew = new IdNameHashMap<>();
        availableCertificateProfilesNew = CertificateRestResourceUtil.loadAllAuthorizedCertificateProfiles(authenticationToken, raMasterApi, availableCertificateProfilesNew);
        KeyToValueHolder<CertificateProfile> holder = availableCertificateProfilesNew.get(profileName);
        Integer profileId;
        if (holder!=null) {
            profileId = holder.getId();
        }else {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), 
                    "Invalid search criteria, unknown certificate profile.");
        }
        final CertificateProfile certProfile = raMasterApi.getCertificateProfile(profileId);
        final List<Integer> caIds = certProfile.getAvailableCAs();
        List<String> availableCas = new ArrayList<String>();
        List<String> availableKeyAlgos = certProfile.getAvailableKeyAlgorithmsAsList();
        List<String> availableEcdsaCurves = new ArrayList<>();
        List<Integer> availableBitLengths = new ArrayList<>();
        // add CA name for all ids...
        for (final int id : caIds) {
            if (id == CertificateProfile.ANYCA) {
                availableCas.add("ANY CA");
            } else {
                final CACommon ca = caSession.getCA(authenticationToken, id, null);
                availableCas.add(ca.getName());
            }
        }
        if (!availableKeyAlgos.contains("ECDSA")) {
            availableEcdsaCurves.add("No EC curves available.");
        }else {
            availableEcdsaCurves = certProfile.getAvailableEcCurvesAsList();
        }
        if ((!availableKeyAlgos.contains("RSA")) && (!availableEcdsaCurves.contains("ANY_EC_CURVE"))) {
            availableBitLengths.add(0);
        }else {
            availableBitLengths = certProfile.getAvailableBitLengthsAsList();
        }
        return CertificateProfileInfoRestResponseV2.builder()
                .setAvailableAlgos(availableKeyAlgos)
                .setAvailableBitLengths(availableBitLengths)
                .setAvailableEcdsaCurves(availableEcdsaCurves)
                .setAvailableProfileCAs(availableCas)
                .build();
    }
}
