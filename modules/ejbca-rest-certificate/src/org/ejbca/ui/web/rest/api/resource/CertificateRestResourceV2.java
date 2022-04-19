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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.era.RaCertificateSearchRequestV2;
import org.ejbca.core.model.era.RaCertificateSearchResponseV2;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestV2;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;
import org.ejbca.ui.web.rest.api.io.response.SearchCertificatesRestResponseV2;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling certificate-related requests version 2.
 */
@Api(tags = {"v2/certificate"}, value = "Certificate REST Management API V2")
@Path("v2/certificate")
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateRestResourceV2 extends BaseRestResource {
    
    private static final String RESOURCE_STATUS = "OK";
    protected static final String RESOURCE_VERSION = "2.0";
    
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
        return Response.ok(RestResourceStatusRestResponse.builder()
                .status(RESOURCE_STATUS)
                .version(RESOURCE_VERSION)
                .revision(GlobalConfiguration.EJBCA_VERSION)
                .build()
        ).build();
    }
    
    @POST
    @Path("/search")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ApiOperation(
            value = "Searches for certificates confirming given criteria and pagination.",
            notes = "Insert as many search criteria as needed. A reference about allowed values for criteria could be found below, under SearchCertificateCriteriaRestRequestV2 model.",
            response = SearchCertificatesRestResponseV2.class
    )
    public Response searchCertificates(
            @Context HttpServletRequest requestContext,
            @ApiParam(value = "Collection of search criterias and pagination information.") final SearchCertificatesRestRequestV2 searchCertificatesRestRequest
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
     * @param restRequest search criteria.
     * @return Search results.
     * @throws RestException In case of malformed criteria.
     * @throws CertificateEncodingException In case of failure in certificate reading.
     * @throws CertificateParsingException if the certificate from Base64CertData cannot be parsed.
     */
    private SearchCertificatesRestResponseV2 searchCertificates(
            final AuthenticationToken authenticationToken,
            final SearchCertificatesRestRequestV2 restRequest
    ) throws RestException, CertificateEncodingException, CertificateParsingException {
        final RaCertificateSearchRequestV2 raRequest = SearchCertificatesRestRequestV2.converter().toEntity(restRequest);
        final RaCertificateSearchResponseV2 raResponse = (RaCertificateSearchResponseV2) raMasterApi.searchForCertificatesV2(authenticationToken, raRequest);
        return SearchCertificatesRestResponseV2.converter().toRestResponse(raResponse, restRequest.getPagination());
    }
}
