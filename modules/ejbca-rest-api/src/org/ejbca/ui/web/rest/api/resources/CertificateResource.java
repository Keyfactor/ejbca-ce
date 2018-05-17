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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.ErrorCode;
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
    
    private static final String VERSION = "1";
    
    private static final Logger log = Logger.getLogger(CertificateResource.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApi;
    
    
    
    @POST
    @Path("/enroll-server-certificate")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response enrollServerCertificate(@Context HttpServletRequest requestContext, EnrollCertificateRequestType enrollcertificateRequest) 
            throws CADoesntExistsException, CertificateProfileDoesNotExistException, EndEntityProfileNotFoundException, AuthorizationDeniedException, CertificateParsingException {
        
        AuthenticationToken authenticationToken = getAdmin(requestContext, false);
        
        EndEntityInformation endEntityInformation = new EndEntityInformation();
        ExtendedInformation extendedInformation = new ExtendedInformation();
        
        // TODO: where to get it, from CRT?
        //extendedInformation.setCertificateEndTime(getUserDefinedValidityIfSpecified());  
        
        endEntityInformation.setExtendedInformation(extendedInformation);
        
        CAInfo caInfo = getCAInfo(enrollcertificateRequest.getCertificateAuthorityId(), authenticationToken);
        if (caInfo == null) {
            throw new CADoesntExistsException();
        }
        endEntityInformation.setCAId(caInfo.getCAId());
        
        if (!certificateProfileExists(enrollcertificateRequest.getCertificateProfileId(), authenticationToken)) {
            throw new CertificateProfileDoesNotExistException();
        }
        endEntityInformation.setCertificateProfileId(enrollcertificateRequest.getCertificateProfileId());
                
        String subjectDn = getSubjectDn(enrollcertificateRequest.getCertificateRequest());
        endEntityInformation.setDN(subjectDn);
        
        EndEntityProfile endEntityProfile = getEndEntityProfile(enrollcertificateRequest.getEndEntityProfileId(), authenticationToken);
        if (endEntityProfile == null) {
            throw new EndEntityProfileNotFoundException();
        }
        endEntityInformation.setEndEntityProfileId(enrollcertificateRequest.getEndEntityProfileId());
        
        endEntityInformation.setCardNumber("");
        endEntityInformation.setHardTokenIssuerId(0);
        endEntityInformation.setStatus(EndEntityConstants.STATUS_NEW);
        
        // TODO: how to get this? 
        // endEntityInformation.setSubjectAltName(subjectAlternativeName.toString());
        
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
        if (StringUtils.isBlank(endEntityInformation.getUsername())) {
            String autousername = new String(Hex.encode(randomData));
            while (raMasterApi.searchUser(authenticationToken, autousername) != null) {
                if(log.isDebugEnabled()){
                    log.debug("Autogenerated username '" + autousername + "' is already reserved. Generating the new one...");
                }
                random.nextBytes(randomData);
                autousername = new String(Hex.encode(randomData));
            }
            if(log.isDebugEnabled()){
                log.debug("Unique username '" + autousername + "' has been generated");
            }
            endEntityInformation.setUsername(autousername);
        }
        if (endEntityProfile.useAutoGeneratedPasswd()) {
            // If auto-generated passwords are used, this is set on the CA side when adding or changing the EE as long as the password is null
            endEntityInformation.setPassword(null);
        } else if (StringUtils.isEmpty(endEntityInformation.getPassword())) {
            // If not needed just use some random data
            random.nextBytes(randomData);
            endEntityInformation.setPassword(new String(Hex.encode(CertTools.generateSHA256Fingerprint(randomData))));
        }
        
        //Add end-entity
        try {
            if (raMasterApi.addUser(authenticationToken, endEntityInformation, /*clearpwd=*/false)) {
                log.info("End entity with username " + endEntityInformation.getUsername() + " has been successfully added by client " + authenticationToken);
            } else {
                log.info("Client " + authenticationToken + " failed to generate certificate for end entity with username " +  endEntityInformation.getUsername());
                return null;
            }
        } catch (AuthorizationDeniedException e) {
            log.info(authenticationToken + " is not authorized to execute this operation", e);
            return null;
        } catch (WaitingForApprovalException e) {
            log.info("Request with ID " + e.getRequestId() + " is still waiting for approval");
            return null;
        } catch(EjbcaException e){
            ErrorCode errorCode = EjbcaException.getErrorCode(e);
            if(errorCode != null){
                if(errorCode.equals(ErrorCode.USER_ALREADY_EXISTS)){
                    log.info("Client " + authenticationToken + " failed to add end entity since the username " + endEntityInformation.getUsername() + " already exists");
                }else{
                    log.info("EjbcaException has been caught. Error Code: " + errorCode, e);
                }
            }else{
                log.info("Client " + authenticationToken +" failed to add end entity " + endEntityInformation.getUsername() + ". Contact your administrator or check the logs.", e);
            }
            return null;
        }
        
        byte[] certificate = null;
        
        try {
            endEntityInformation.getExtendedInformation().setCertificateRequest(CertTools.getCertificateRequestFromPem(enrollcertificateRequest.getCertificateRequest()).getEncoded());
            certificate = raMasterApi.createCertificate(authenticationToken, endEntityInformation);
        } catch (IOException e) {
            // TODO
            e.printStackTrace();
        } catch (AuthorizationDeniedException e) {
            // TODO
            e.printStackTrace();
        } catch (EjbcaException e) {
            // TODO
            e.printStackTrace();
        }
        X509Certificate cert = CertTools.getCertfromByteArray(certificate, X509Certificate.class);
        return Response.ok(cert.toString()).build();   
    }
    
    
    private String getSubjectDn(String csr) {
        String subject = "";
        final PKCS10CertificationRequest pkcs10CertificateRequest = CertTools.getCertificateRequestFromPem(csr);
        if (pkcs10CertificateRequest == null) {
            throw new IllegalArgumentException("Invalid CSR");
        }
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
     * Returns the validity string specified by the user or null if one of the
     * following conditions hold:
     * <ul>
     * <li>Validity override is disabled in the certificate profile</li>
     * <li>User defined validity is disabled in the UI</li>
     * <li>The validity cannot be parsed (invalid format)</li>
     * <li>The validity exceeds the maximum validity as specified by the certificate profile</li>
     * <ul>
     * @return The validity as a string or null
     */
    /*
    private String getUserDefinedValidityIfSpecified() {
        if (!isValidityOverrideEnabled()) {
            return null;
        }
        if (!isSetCustomValidity()) {
            return null;
        }
        final Date anchorDate = new Date();
        final String validityToCheck = validity;
        final Date userDate = ValidityDate.getDate(validityToCheck, anchorDate);
        if (userDate == null) {
            return null;
        }
        final Date maxDate = ValidityDate.getDate(getCertificateProfile().getEncodedValidity(), anchorDate);
        if (userDate.after(maxDate)) {
            return null;
        }
        return validityToCheck;
    }
    */
    
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
    
    @GET
    @Path("/version")
    @Produces("text/html")
    public String version() {
        return VERSION;
    }
}
