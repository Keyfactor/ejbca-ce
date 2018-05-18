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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.ui.web.protocol.DateNotValidException;
import org.ejbca.ui.web.rest.api.types.EnrollCertificateRequestType;
import org.ejbca.ui.web.rest.api.types.EnrollCertificateResponseType;
import org.ejbca.ui.web.rest.api.types.RevocationResultType;
import org.ejbca.ui.web.rest.common.BaseRestResource;

/**
 * JAX-RS resource handling certificate-related requests.
 * @version $Id$
 *
 */
@Path("v1/certificate")
@Stateless
public class CertificateResource extends BaseRestResource {
    
    private static final Logger log = Logger.getLogger(CertificateResource.class);
    
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    
    
    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
    @Override
    public Response status() {
        return super.status();
    }
    
    @POST
    @Path("/enroll")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enrollServerCertificate(@Context HttpServletRequest requestContext, EnrollCertificateRequestType enrollcertificateRequest) {
        
        AuthenticationToken authenticationToken;
        try {
            authenticationToken = getAdmin(requestContext, false);
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        }
        
        EndEntityInformation endEntityInformation = new EndEntityInformation();
        ExtendedInformation extendedInformation = new ExtendedInformation();
        
        endEntityInformation.setExtendedInformation(extendedInformation);
        
        CAInfo caInfo = getCAInfo(enrollcertificateRequest.getCertificateAuthorityId(), authenticationToken);
        if (caInfo == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new CADoesntExistsException()).build();
        }
        endEntityInformation.setCAId(caInfo.getCAId());
        
        if (!certificateProfileExists(enrollcertificateRequest.getCertificateProfileId(), authenticationToken)) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new CertificateProfileDoesNotExistException()).build();
        }
        endEntityInformation.setCertificateProfileId(enrollcertificateRequest.getCertificateProfileId());
                
        
        PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(enrollcertificateRequest.getCertificateRequest());
        if (pkcs10CertificateRequest == null) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
        
        String altName = getSubjectAltName(pkcs10CertificateRequest);
        endEntityInformation.setSubjectAltName(altName);
        
        String subjectDn = getSubjectDn(pkcs10CertificateRequest);
        endEntityInformation.setDN(subjectDn);
        
        EndEntityProfile endEntityProfile = getEndEntityProfile(enrollcertificateRequest.getEndEntityProfileId(), authenticationToken);
        if (endEntityProfile == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new EndEntityProfileNotFoundException()).build();
        }
        endEntityInformation.setEndEntityProfileId(enrollcertificateRequest.getEndEntityProfileId());
        
        endEntityInformation.setCardNumber("");
        endEntityInformation.setHardTokenIssuerId(0);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        
        Date timecreated = new Date();
        endEntityInformation.setTimeCreated(timecreated);
        endEntityInformation.setTimeModified(timecreated);
        
        endEntityInformation.setType(new EndEntityType(EndEntityTypes.ENDUSER));
        
        // sendnotification, keyrecoverable and print must be set after setType, because it adds to the type
        boolean isSendNotificationDefaultInProfile = EndEntityProfile.TRUE.equals(endEntityProfile.getValue(EndEntityProfile.SENDNOTIFICATION, 0));
        endEntityInformation.setSendNotification(isSendNotificationDefaultInProfile && !endEntityInformation.getSendNotification());
        
        boolean isKeyRecoverableDefaultInProfile = EndEntityProfile.TRUE.equals(endEntityProfile.getValue(EndEntityProfile.KEYRECOVERABLE, 0));
        endEntityInformation.setKeyRecoverable(isKeyRecoverableDefaultInProfile && !endEntityInformation.getKeyRecoverable());
        
        endEntityInformation.setPrintUserData(false);
        endEntityInformation.setTokenType(EndEntityConstants.TOKEN_USERGEN);

        
        // Fill end-entity information (Username and Password)
        final byte[] randomData = new byte[16];
        final Random random = new SecureRandom();
        random.nextBytes(randomData);
        if (StringUtils.isBlank(enrollcertificateRequest.getUsername())) {
            String autousername = new String(Hex.encode(randomData));
            while (raMasterApi.searchUser(authenticationToken, autousername) != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Autogenerated username '" + autousername + "' is already reserved. Generating the new one...");
                }
                random.nextBytes(randomData);
                autousername = new String(Hex.encode(randomData));
            }
            if (log.isDebugEnabled()) {
                log.debug("Unique username '" + autousername + "' has been generated");
            }
            endEntityInformation.setUsername(autousername);
        } else {
            endEntityInformation.setUsername(enrollcertificateRequest.getUsername());
        }
        
        
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
        
        //Add end-entity
        try {
            if (raMasterApi.addUser(authenticationToken, endEntityInformation, /*clearpwd=*/false)) {
                log.info("End entity with username " + endEntityInformation.getUsername() + " has been successfully added by client " + authenticationToken);
            } else {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (WaitingForApprovalException e) {
            return Response.status(Response.Status.ACCEPTED).entity(e).build();
        } catch(EjbcaException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e).build();
        }
        
        byte[] certificate = null;
        
        try {
            endEntityInformation.getExtendedInformation().setCertificateRequest(CertTools.getCertificateRequestFromPem(enrollcertificateRequest.getCertificateRequest()).getEncoded());
            certificate = raMasterApi.createCertificate(authenticationToken, endEntityInformation);
        } catch (IOException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (EjbcaException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new EndEntityProfileNotFoundException()).build();
        }
        X509Certificate cert;
        try {
            cert = CertTools.getCertfromByteArray(certificate, X509Certificate.class);
        } catch (CertificateParsingException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        }
        
        EnrollCertificateResponseType enrollCertificateResponse = null;
        try {
            enrollCertificateResponse = new EnrollCertificateResponseType(cert.getEncoded(), cert.getSerialNumber());
        } catch (CertificateEncodingException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
        return Response.ok(enrollCertificateResponse).build();
        
        // TODO Response codes will be handled properly with ECA-6937, ECA-6938.
    }


    private String getSubjectAltName(PKCS10CertificationRequest pkcs10CertificateRequest) {
        String altName = null;
        final Extension subjectAlternativeNameExtension = CertTools.getExtension(pkcs10CertificateRequest, Extension.subjectAlternativeName.getId());
        if (subjectAlternativeNameExtension!=null) {
            altName = CertTools.getAltNameStringFromExtension(subjectAlternativeNameExtension);
        }
        return altName;
    }
    
    
    private String getSubjectDn(PKCS10CertificationRequest pkcs10CertificateRequest) {
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
     * @param requestContext HttpServletRequest
     * @param issuerDN of the certificate to revoke
     * @param serialNumber decimal serial number
     * @param reason revocation reason. 
     * @see org.cesecore.certificates.crl.RevocationReasons
     * @param date revocation date (optional). Must be valid ISO8601 date string
     * @return JSON representation of serialNr, revocation status, date and optional message
     */
    @PUT
    @Path("/{issuer_dn}/{certificate_serial_number}/revoke")
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeCertificate(
            @Context HttpServletRequest requestContext,
            @PathParam("issuer_dn") String issuerDN,
            @PathParam("certificate_serial_number") String serialNumber,
            @QueryParam("reason") String reason,
            @QueryParam("date") String date) {
        Date revocationDate = null;
        final BigInteger serianNr = new BigInteger(serialNumber);
        RevocationResultType result = new RevocationResultType(serianNr, RevocationResultType.STATUS_REVOKED);
        RevocationReasons reasons = RevocationReasons.getFromCliValue(reason);
        if (reasons == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid revocation reason").build();
        }
        final int revocationReason = reasons.getDatabaseValue();
        try {
            final AuthenticationToken admin = getAdmin(requestContext, false);
            if (date != null) {
                revocationDate = getValidatedRevocationDate(date);
                result.setDate(revocationDate);
            } else {
                result.setDate(new Date());
            }
            raMasterApi.revokeCert(admin, serianNr, revocationDate, issuerDN, revocationReason, false);
            result.setMessage("Successfully revoked");
        } catch (AuthorizationDeniedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (AlreadyRevokedException e) {
            result.setStatus(RevocationResultType.STATUS_ALREADYREVOKED);
            result.setMessage("Certificate has already been revoked");
        } catch (WaitingForApprovalException e) {
            result.setStatus(RevocationResultType.STATUS_WAITINGFORAPPROVAL);
            result.setMessage("Operation is awaiting approval by another administrator");
        } catch (NoSuchEndEntityException | ApprovalException | RevokeBackDateNotAllowedForProfileException | CADoesntExistsException | DateNotValidException e) {
            result.setStatus(RevocationResultType.STATUS_ERROR);
            result.setMessage(e.getMessage());
        } 
        // TODO Response codes will be handled properly with ECA-6937, ECA-6938.
        return Response.ok(result).build();
    }
    
    private Date getValidatedRevocationDate(String sDate) throws DateNotValidException {
        Date date = null;
        if (sDate != null) {
            try {
                date = DatatypeConverter.parseDateTime(sDate).getTime();
            } catch (IllegalArgumentException e) {
                throw new DateNotValidException(intres.getLocalizedMessage("ra.bad.date", sDate));
            }
            if (date.after(new Date())) {
                throw new DateNotValidException("Revocation date in the future: '" + sDate + "'.");
            }
        }
        return date;
    }
}
