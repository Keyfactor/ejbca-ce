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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.math.IntRange;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.CaInfoRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CaInfosRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CreateCrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.RestResourceStatusRestResponse;

import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;

/**
 * JAX-RS resource handling CA related requests.
 *
 * @version $Id$
 */
@Path("/v1/ca")
@Produces(MediaType.APPLICATION_JSON)
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CaRestResource extends BaseRestResource {
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    @GET
    @Path("/status")
    @ApiOperation(value = "Get the status of this REST Resource",
                  notes = "Returns status, API version and EJBCA version.",
                  response = RestResourceStatusRestResponse.class)
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
    @ApiOperation(value = "Get PEM file with the active CA certificate chain")
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
    
    @POST
    @Path("/{issuer_dn}/createcrl")
    @ApiOperation(value = "Create CRL(main, partition and delta) issued by this CA", response=CreateCrlRestResponse.class)
    public Response createCrl(@Context HttpServletRequest httpServletRequest,
                                 @ApiParam(value = "the CRL issuers DN (CAs subject DN)", required = true) @PathParam("issuer_dn") String issuerDn,
                                 @ApiParam(value = "true to also create the deltaCRL, false to only create the base CRL", required = false, defaultValue = "false")
                                 @QueryParam("deltacrl") boolean deltacrl
    ) throws AuthorizationDeniedException, RestException, EjbcaException, CADoesntExistsException {
        final AuthenticationToken admin = getAdmin(httpServletRequest, false);
        issuerDn = issuerDn.trim();
        int caId = issuerDn.hashCode();
        
        CAInfo cainfo = caSession.getCAInfo(admin, caId);
        if (cainfo == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), 
                    "CA with DN: " + issuerDn + " does not exist.");
        }
        
        CreateCrlRestResponse response = new CreateCrlRestResponse();
        response.setIssuerDn(issuerDn);
        
        boolean result = true;
        try {
            result &= publishingCrlSession.forceCRL(admin, caId); // always generated
            if(deltacrl) { // generated on top of base CRL
                result &= publishingCrlSession.forceDeltaCRL(admin, caId);
            }
        } catch (CADoesntExistsException | CryptoTokenOfflineException | CAOfflineException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), 
                    e.getMessage());
        }
        response.setAllSuccess(result);
        response.setLatestCrlVersion(crlStoreSession.getLastCRLNumber(issuerDn, 
                CertificateConstants.NO_CRL_PARTITION, false));
        response.setLatestDeltaCrlVersion(crlStoreSession.getLastCRLNumber(issuerDn, 
                CertificateConstants.NO_CRL_PARTITION, true));
        
        final CAInfo caInfo = caSession.getCAInfo(admin, caId);
        IntRange crlPartitions = caInfo != null ? caInfo.getAllCrlPartitionIndexes() : null;
        if (crlPartitions != null) {
            Map<String, Integer> latestPartitionCrlVersions = new HashMap<>();
            Map<String, Integer> latestPartitionDeltaCrlVersions = new HashMap<>();
            
            for (int crlPartitionIndex = crlPartitions.getMinimumInteger(); 
                    crlPartitionIndex <= crlPartitions.getMaximumInteger(); crlPartitionIndex++) {
                latestPartitionCrlVersions.put("partition_" + crlPartitionIndex, 
                        crlStoreSession.getLastCRLNumber(issuerDn, crlPartitionIndex, false));
                // always included, CRL for deltaCrl or otherwise
                latestPartitionDeltaCrlVersions.put("partition_" + crlPartitionIndex, 
                        crlStoreSession.getLastCRLNumber(issuerDn, crlPartitionIndex, true));
            }
            
            response.setLatestPartitionCrlVersions(latestPartitionCrlVersions);
            response.setLatestPartitionDeltaCrlVersions(latestPartitionDeltaCrlVersions);
        }
        
        return Response.ok(response).build();
    }
    
}
