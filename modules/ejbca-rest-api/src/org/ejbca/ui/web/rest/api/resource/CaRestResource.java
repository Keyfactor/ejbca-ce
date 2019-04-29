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

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.CaInfoRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CaInfosRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling CA related requests.
 *
 * @version $Id$
 */
@Api(tags = {"v1/ca"}, value = "Certificate Rest Management API")
/* Swagger description etc is available in the CertificateRestResource */
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CaRestResource extends BaseRestResource {

    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource", response = RestResourceStatusRestResponse.class)
    @Override
    public Response status() {
        return super.status();
    }

    /**
     * @param subjectDn CA subjectDn
     * @return PEM file with CA certificates
     */
    @GET
    @Path("/{subject_dn}/certificate/download")
    @Produces(MediaType.WILDCARD)
    @ApiOperation(value = "Get PEM file with CA certificates")
    public Response getCertificateAsPem(@Context HttpServletRequest requestContext,
                                        @ApiParam(value = "CAs subject DN", required = true) @PathParam("subject_dn") String subjectDn)
            throws AuthorizationDeniedException, CertificateEncodingException, CADoesntExistsException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        subjectDn = CertTools.stringToBCDNString(subjectDn);
        Collection<Certificate> certificateChain = EJBTools.unwrapCertCollection(raMasterApiProxy.getCertificateChain(admin, subjectDn.hashCode()));

        byte[] bytes = CertTools.getPemFromCertificateChain(certificateChain);
        return Response.ok(bytes)
                .header("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(subjectDn + ".cacert.pem") + "\"")
                .header("Content-Length", bytes.length)
                .build();
    }

    /**
     * Returns the Response containing the list of CAs with general information per CA as Json.
     *
     * @param httpServletRequest HttpServletRequest of a request.
     *
     * @return The response containing the list of CAs and its general information.
     */
    @GET
    @ApiOperation(value = "Returns the Response containing the list of CAs with general information per CA as Json",
        notes = "Returns the Response containing the list of CAs with general information per CA as Json",
        response = CaInfosRestResponse.class)
    public Response listCas(@Context final HttpServletRequest httpServletRequest) throws AuthorizationDeniedException, CADoesntExistsException, RestException {
        final AuthenticationToken adminToken = getAdmin(httpServletRequest, false);
        List<CaInfoRestResponse> caInfoRestResponseList = CaInfosRestResponse.converter().toRestResponses(raMasterApiProxy.getAuthorizedCAInfos(adminToken));
        final CaInfosRestResponse caInfosRestResponse = CaInfosRestResponse.builder()
                .certificateAuthorities(caInfoRestResponseList)
                .build();
        return Response.ok(caInfosRestResponse).build();
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
        final AuthenticationToken adminToken = getAdmin(httpServletRequest, true);
        RaCrlSearchRequest request = new RaCrlSearchRequest();
        request.setIssuerDn(issuerDn);
        request.setCrlPartitionIndex(crlPartitionIndex);
        request.setDeltaCRL(deltaCrl);
        byte[] latestCrl = raMasterApiProxy.getLatestCrlByRequest(adminToken, request);
        CrlRestResponse restResponse = CrlRestResponse.builder().setCrl(latestCrl).setResponseFormat("DER").build();
        return Response.ok(restResponse).build();
    }

}
