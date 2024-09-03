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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.core.EntityPart;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlImportException;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.DeltaCrlException;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.ejbca.core.ejb.crl.CrlCreationParams;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaCaListRequest;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.io.response.CaInfoRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CaInfosRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CreateCrlRestResponse;
import org.ejbca.ui.web.rest.api.io.response.CrlRestResponse;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * JAX-RS resource handling CA related requests.
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CaRestResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(CaRestResource.class);
    private static final int MAX_CRL_FILE_SIZE = 1024 * 1024 * 50; // 50MB
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxy;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private ImportCrlSessionLocal importCrlSession;

    /**
     * @param subjectDn CA subjectDn
     * @return PEM file with CA certificates
     */
    public Response getCertificateAsPem(final HttpServletRequest requestContext, String subjectDn)
            throws AuthorizationDeniedException, CertificateEncodingException, CADoesntExistsException, RestException {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        subjectDn = DnComponents.stringToBCDNString(subjectDn);
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
     * @param includeExternal boolean true to get external cartificates, false to not include external certificates
     * @return The response containing the list of CAs and its general information.
     */
    public Response listCas(final HttpServletRequest httpServletRequest, boolean includeExternal) throws AuthorizationDeniedException, CADoesntExistsException, RestException {
        final AuthenticationToken adminToken = getAdmin(httpServletRequest, false);
        final RaCaListRequest raCaListRequest = new RaCaListRequest();
        raCaListRequest.setIncludeExternal(includeExternal);
        final IdNameHashMap<CAInfo> authorizedCAInfos = raMasterApiProxy.getRequestedAuthorizedCAInfos(adminToken, raCaListRequest);
        final List<CaInfoRestResponse> caInfoRestResponseList = CaInfosRestResponse.converter().toRestResponses(authorizedCAInfos);
        final CaInfosRestResponse caInfosRestResponse = CaInfosRestResponse.builder()
                .certificateAuthorities(caInfoRestResponseList)
                .build();
        return Response.ok(caInfosRestResponse).build();
    }

    public Response getLatestCrl(final HttpServletRequest httpServletRequest,
                                 final String issuerDn,
                                 final boolean deltaCrl,
                                 final int crlPartitionIndex
    ) throws AuthorizationDeniedException, RestException, CADoesntExistsException {
        final AuthenticationToken adminToken = getAdmin(httpServletRequest, true);
        RaCrlSearchRequest request = new RaCrlSearchRequest();
        request.setIssuerDn(issuerDn);
        request.setCrlPartitionIndex(crlPartitionIndex);
        request.setDeltaCRL(deltaCrl);
        byte[] latestCrl = raMasterApiProxy.getLatestCrlByRequest(adminToken, request);
        CrlRestResponse restResponse = CrlRestResponse.builder().setCrl(latestCrl).setResponseFormat("DER").build();
        return Response.ok(restResponse).build();
    }

    public Response createCrl(final HttpServletRequest httpServletRequest, String issuerDn, final boolean deltacrl
    ) throws AuthorizationDeniedException, RestException, CADoesntExistsException {
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
            if (deltacrl) {
                // generate delta CRL
                result &= publishingCrlSession.forceDeltaCRL(admin, caId);
            } else {
                // if false, generate base CRL
                result &= publishingCrlSession.forceCRL(admin, caId, new CrlCreationParams(5, TimeUnit.MINUTES));
            }
        } catch (CADoesntExistsException | CryptoTokenOfflineException | CAOfflineException | DeltaCrlException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(),
                    e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
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

    public Response importCrl(final HttpServletRequest httpServletRequest, String issuerDn, final EntityPart crlPartitionIndexEP, final EntityPart crlFileEP)
            throws AuthorizationDeniedException, RestException {
        final AuthenticationToken admin = getAdmin(httpServletRequest, false);

        issuerDn = issuerDn.trim();
        final CAInfo cainfo = caSession.getCAInfo(admin, issuerDn.hashCode());

        if (cainfo == null) {
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "CA with DN: " + issuerDn + " does not exist.");
        }

        try {
            final int crlPartitionIndex = Integer.parseInt(crlPartitionIndexEP.getContent(String.class));
            final File crlFile = crlFileEP == null? null : crlFileEP.getContent(File.class);

            if (crlPartitionIndex < 0) {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(),
                                        "Invalid CRL partition index: Partition index should be a number of 0 or greater.");
            }

            if (crlFile == null) {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "No CRL file uploaded.");
            }

            final byte[] crlFileBytes = FileUtils.readFileToByteArray(crlFile);
            final X509CRL x509crl = CertTools.getCRLfromByteArray(crlFileBytes);

            if (x509crl == null) {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Could not parse CRL. It must be in DER format.");
            } else if (!StringUtils.equals(cainfo.getSubjectDN(), CertTools.getIssuerDN(x509crl))) {
                throw new RestException(Status.BAD_REQUEST.getStatusCode(), "CRL is not issued by " + issuerDn);
            } else {
                final int uploadedCrlNumber = CrlExtensions.getCrlNumber(x509crl).intValue();
                final boolean isDeltaCrl = CrlExtensions.getDeltaCRLIndicator(x509crl).intValue() != -1;

                if (uploadedCrlNumber <= crlStoreSession.getLastCRLNumber(issuerDn, crlPartitionIndex, isDeltaCrl)) {
                    throw new RestException(Status.BAD_REQUEST.getStatusCode(),
                            "CRL #" + uploadedCrlNumber + " or higher is already in the database.");
                }

                importCrlSession.importCrl(admin, cainfo, crlFileBytes, crlPartitionIndex);
                return Response.status(Status.OK).build();
            }
        } catch (NumberFormatException e) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid CRL partition index: Partition index should be a number of 0 or greater.");
        } catch (CrlImportException | CrlStoreException | CRLException | AuthorizationDeniedException e) {
            log.info("Error importing CRL:", e);
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "Error while importing CRL: " + e.getMessage());
        } catch (IOException e) {
            log.info("Error uploading CRL file", e);
            throw new RestException(Status.BAD_REQUEST.getStatusCode(), "No file uploaded.");
        }
    }
}
