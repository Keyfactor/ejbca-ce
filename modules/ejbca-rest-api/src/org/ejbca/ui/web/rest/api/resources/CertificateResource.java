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

package org.ejbca.ui.web.rest.api.resources;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Random;

import javax.ejb.EJB;
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
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.web.rest.api.converters.CertificateConverter;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.types.CertificateResponse;
import org.ejbca.ui.web.rest.api.types.CertificateTypes;
import org.ejbca.ui.web.rest.api.types.EnrollCertificateRequestType;
import org.ejbca.ui.web.rest.api.types.ResponseStatus;
import org.ejbca.ui.web.rest.api.types.RevocationResultType;
import org.ejbca.ui.web.rest.api.types.response.ExpiringCertificatesResponse;
import org.ejbca.ui.web.rest.common.BaseRestResource;

/**
 * JAX-RS resource handling certificate-related requests.
 *
 * @version $Id$
 */
@Path("v1/certificate")
@Stateless
public class CertificateResource extends BaseRestResource {

    private static final Logger log = Logger.getLogger(CertificateResource.class);
    /**
     * Internal localization of logs and errors
     */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private final CertificateConverter certificateConverter;

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;


    public CertificateResource() {
        this.certificateConverter = new CertificateConverter();
    }

    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public Response status() {
        return super.status();
    }

    @POST
    @Path("/pkcs10enroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enrollPkcs10Certificate(@Context HttpServletRequest requestContext, EnrollCertificateRequestType enrollcertificateRequest) 
            throws RestException, AuthorizationDeniedException {

        try {
            AuthenticationToken authenticationToken = getAdmin(requestContext, false);
            EndEntityInformation endEntityInformation = fillEndEntityInformation(enrollcertificateRequest, authenticationToken);
            
            addEndEntity(authenticationToken, endEntityInformation);
            
            endEntityInformation.getExtendedInformation().setCertificateRequest(CertTools.getCertificateRequestFromPem(enrollcertificateRequest.getCertificateRequest()).getEncoded());
            byte[] certificate = raMasterApi.createCertificate(authenticationToken, endEntityInformation);
            
            X509Certificate cert = CertTools.getCertfromByteArray(certificate, X509Certificate.class);
            
            CertificateResponse enrollCertificateResponse = certificateConverter.toType(cert);
            return Response.ok(enrollCertificateResponse).build();
        } catch (EjbcaException | WaitingForApprovalException | CertificateParsingException | IOException | CertificateEncodingException e){
            throw new RestException(400, e.getMessage());
        }
    }

    private void addEndEntity(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException, RestException {
        if (raMasterApi.addUser(authenticationToken, endEntityInformation, /*clearpwd=*/false)) {
            log.info("End entity with username " + endEntityInformation.getUsername() + " has been successfully added by client " + authenticationToken);
        } else {
            throw new RestException(422, "Problem with adding end entity with username " + endEntityInformation.getUsername());
        }
    }

    private EndEntityInformation fillEndEntityInformation(EnrollCertificateRequestType enrollcertificateRequest, AuthenticationToken authenticationToken) throws RestException {
        EndEntityInformation endEntityInformation = new EndEntityInformation();
        ExtendedInformation extendedInformation = new ExtendedInformation();

        endEntityInformation.setExtendedInformation(extendedInformation);

        CAInfo caInfo = getCAInfo(enrollcertificateRequest.getCertificateAuthorityId(), authenticationToken);
        if (caInfo == null) {
            throw new RestException(422, "CA with id " + enrollcertificateRequest.getCertificateAuthorityId() + " doesn't exist");
        }
        endEntityInformation.setCAId(caInfo.getCAId());

        if (!certificateProfileExists(enrollcertificateRequest.getCertificateProfileId(), authenticationToken)) {
            throw new RestException(422, "Certificate profile with id " + enrollcertificateRequest.getCertificateProfileId() + " doesn't exist");
        }
        endEntityInformation.setCertificateProfileId(enrollcertificateRequest.getCertificateProfileId());
        
        PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(enrollcertificateRequest.getCertificateRequest());
        if (pkcs10CertificateRequest == null) {
            throw new RestException(422, "Invalid certificate request");
        }
        
        String altName = getSubjectAltName(pkcs10CertificateRequest);
        endEntityInformation.setSubjectAltName(altName);
        
        String subjectDn = getSubjectDn(pkcs10CertificateRequest);
        endEntityInformation.setDN(subjectDn);
        
        EndEntityProfile endEntityProfile = getEndEntityProfile(enrollcertificateRequest.getEndEntityProfileId(), authenticationToken);
        if (endEntityProfile == null) {
            throw new RestException(422, "End entity profile with id " + enrollcertificateRequest.getEndEntityProfileId() + "doesn't exist");
        }
        endEntityInformation.setEndEntityProfileId(enrollcertificateRequest.getEndEntityProfileId());
        
        endEntityInformation.setCardNumber("");
        endEntityInformation.setHardTokenIssuerId(0);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);

        Date timecreated = new Date();
        endEntityInformation.setTimeCreated(timecreated);
        endEntityInformation.setTimeModified(timecreated);
        
        endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER));
        boolean isSendNotificationDefaultInProfile = EndEntityProfile.TRUE.equals(endEntityProfile.getValue(EndEntityProfile.SENDNOTIFICATION, 0));
        endEntityInformation.setSendNotification(isSendNotificationDefaultInProfile && !endEntityInformation.getSendNotification());

        endEntityInformation.setPrintUserData(false);
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_USERGEN);


        // Fill end-entity information (Username and Password)
        final byte[] randomData = new byte[16];
        final Random random = new SecureRandom();
        
        if (endEntityProfile.useAutoGeneratedPasswd()) {
            // If auto-generated passwords are used, this is set on the CA side when adding or changing the EE as long as the password is null
            endEntityInformation.setPassword(null);
        } else if (StringUtils.isEmpty(enrollcertificateRequest.getPassword())) {
            // If not needed just use some random data
            random.nextBytes(randomData);
            endEntityInformation.setPassword(new String(Hex.encode(CertTools.generateSHA256Fingerprint(randomData))));
        } else {
            endEntityInformation.setPassword(enrollcertificateRequest.getPassword());
        }
        return endEntityInformation;
    }


    protected String getSubjectAltName(PKCS10CertificationRequest pkcs10CertificateRequest) {
        String altName = null;
        final Extension subjectAlternativeNameExtension = CertTools.getExtension(pkcs10CertificateRequest, Extension.subjectAlternativeName.getId());
        if (subjectAlternativeNameExtension != null) {
            altName = CertTools.getAltNameStringFromExtension(subjectAlternativeNameExtension);
        }
        return altName;
    }


    protected String getSubjectDn(PKCS10CertificationRequest pkcs10CertificateRequest) {
        String subject = "";
        if (pkcs10CertificateRequest.getSubject() != null) {
            subject = pkcs10CertificateRequest.getSubject().toString();
        }
        return subject;
    }

    private CAInfo getCAInfo(int certificateAuthorityId, AuthenticationToken authenticationToken) {
        IdNameHashMap<CAInfo> authorizedCAInfos = raMasterApi.getAuthorizedCAInfos(authenticationToken);
        KeyToValueHolder<CAInfo> caInfo = authorizedCAInfos.get(certificateAuthorityId);

        if (caInfo != null) {
            return caInfo.getValue();
        }
        return null;
    }

    public EndEntityProfile getEndEntityProfile(int endEntityProfileId, AuthenticationToken authenticationToken) {
        IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = raMasterApi.getAuthorizedEndEntityProfiles(authenticationToken, AccessRulesConstants.CREATE_END_ENTITY);
        KeyToValueHolder<EndEntityProfile> endEntityProfile = authorizedEndEntityProfiles.get(endEntityProfileId);
        if (endEntityProfile != null) {
            return endEntityProfile.getValue();
        }
        return null;
    }

    private boolean certificateProfileExists(int certificateProfileId, AuthenticationToken authenticationToken) {
        IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = raMasterApi.getAuthorizedCertificateProfiles(authenticationToken);
        KeyToValueHolder<CertificateProfile> certificateProfile = authorizedCertificateProfiles.get(certificateProfileId);
        return certificateProfile != null;
    }


    /**
     * Revokes the specified certificate
     *
     * @param requestContext HttpServletRequest
     * @param issuerDN       of the certificate to revoke
     * @param serialNumber   decimal serial number
     * @param reason         revocation reason.
     * @param date           revocation date (optional). Must be valid ISO8601 date string
     * @return JSON representation of serialNr, revocation status, date and optional message
     * @see org.cesecore.certificates.crl.RevocationReasons
     */
    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @PathParam("issuer_dn") String issuerDN,
            @PathParam("certificate_serial_number") String serialNumber,
            @QueryParam("reason") String reason,
            @QueryParam("date") String date) throws Exception {
        final AuthenticationToken admin = getAdmin(requestContext, false);
        RevocationReasons reasons = RevocationReasons.getFromCliValue(reason);
        // TODO Replace with @ValidRevocationReason
        if (reasons == null) {
            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid revocation reason.");
        }
        final int revocationReason = reasons.getDatabaseValue();
        final BigInteger serialNr = new BigInteger(serialNumber);
        Date revocationDate;
        if (date != null) {
            revocationDate = getValidatedRevocationDate(date);
        } else {
            revocationDate = new Date();
        }
        raMasterApi.revokeCert(admin, serialNr, revocationDate, issuerDN, revocationReason, false);
        final RevocationResultType result = new RevocationResultType(serialNr, revocationDate, RevocationResultType.STATUS_REVOKED, "Successfully revoked");
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
    public Response getCertificatesAboutToExpire(@Context HttpServletRequest requestContext,
                                                 @QueryParam("days") long days,
                                                 @QueryParam("offset") int offset,
                                                 @QueryParam("maxNumberOfResults") int maxNumberOfResults) {
        if (requestContext == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing request context").build();
        }
        try {
            final AuthenticationToken admin = getAdmin(requestContext, true);
            int count = raMasterApi.getCountOfCertificatesByExpirationTime(admin, days);
            List<Certificate> expiringCertificates = raMasterApi.getCertificatesByExpirationTime(admin, days, maxNumberOfResults, offset);
            int processedResults = offset + maxNumberOfResults;
            ResponseStatus responseStatus = ResponseStatus.builder().setMoreResults(count > processedResults)
                    .setNextOffset(offset + maxNumberOfResults + 1)
                    .setNumberOfResults(count - processedResults)
                    .build();
            CertificateTypes certificateTypes = new CertificateTypes(certificateConverter.toTypes(expiringCertificates));
            ExpiringCertificatesResponse response = new ExpiringCertificatesResponse(responseStatus, certificateTypes);
            return Response.ok(response).build();
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (CertificateEncodingException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }

    }
}
