/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTAuditLogCallback;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * Session bean for creating certificates.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateCreateSessionBean implements CertificateCreateSessionLocal, CertificateCreateSessionRemote {

    private static final Logger log = Logger.getLogger(CertificateCreateSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;

    /** Default create for SessionBean without any creation Arguments. */
    @PostConstruct
    public void postConstruct() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Override
    public CertificateResponseMessage createCertificate(final AuthenticationToken admin, final EndEntityInformation endEntityInformation, final CA ca,
            final RequestMessage req, final Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams, final long updateTime) throws CryptoTokenOfflineException,
            SignRequestSignatureException, IllegalKeyException, IllegalNameException, CustomCertificateSerialNumberException,
            CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, AuthorizationDeniedException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(IRequestMessage, CA)");
        }
        CertificateResponseMessage ret = null;
        try {
            final CAToken catoken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
            final String alias = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(alias), cryptoToken.getEncProviderName());
            }
            // Verify the request
            final PublicKey reqpk;
            try {
                if (!req.verify()) {
                    throw new SignRequestSignatureException(intres.getLocalizedMessage("createcert.popverificationfailed"));
                }
                reqpk = req.getRequestPublicKey();
                if (reqpk == null) {
                    final String msg = intres.getLocalizedMessage("createcert.nokeyinrequest");
                    throw new InvalidKeyException(msg);
                }
            } catch (InvalidKeyException e) {
                // If we get an invalid key exception here, we should throw an IllegalKeyException to the caller
                // The catch of InvalidKeyException in the end of this method, catches error from the CA crypto token
                throw new IllegalKeyException(e);
            }

            final Date notBefore = req.getRequestValidityNotBefore(); // Optionally requested validity
            final Date notAfter = req.getRequestValidityNotAfter(); // Optionally requested validity
            final Extensions exts = req.getRequestExtensions(); // Optionally requested extensions
            int keyusage = -1;
            if (exts != null) {
                if (log.isDebugEnabled()) {
                    log.debug("we have extensions, see if we can override KeyUsage by looking for a KeyUsage extension in request");
                }
                final Extension ext = exts.getExtension(Extension.keyUsage);
                if (ext != null) {
                    final ASN1OctetString os = ext.getExtnValue();
                        DERBitString bs;
                        try {
                            bs = new DERBitString(os.getEncoded());
                        } catch (IOException e) {
                            throw new IllegalStateException("Unexpected IOException caught.");
                        }
                        keyusage = bs.intValue();
                    if (log.isDebugEnabled()) {
                        log.debug("We have a key usage request extension: " + keyusage);
                    }
                }
            }
            String sequence = null;
            byte[] ki = req.getRequestKeyInfo();
            // CVC sequence is only 5 characters, don't fill with a lot of garbage here, it must be a readable string
            if ((ki != null) && (ki.length > 0) && (ki.length < 10) ) {
                final String str = new String(ki);
                // A cvc sequence must be ascii printable, otherwise it's some binary data
                if (StringUtils.isAsciiPrintable(str)) {
                    sequence = new String(ki);                  
                }
            }
            
            CertificateDataWrapper certWrapper = createCertificate(admin, endEntityInformation, ca, req, reqpk, keyusage, notBefore, notAfter, exts, sequence, certGenParams, updateTime);
            // Create the response message with all nonces and checks etc
            ret = ResponseMessageUtils.createResponseMessage(responseClass, req, ca.getCertificateChain(), cryptoToken.getPrivateKey(alias), cryptoToken.getEncProviderName());
            ResponseStatus status = ResponseStatus.SUCCESS;
            FailInfo failInfo = null;
            String failText = null;
            if ((certWrapper == null) && (status == ResponseStatus.SUCCESS)) {
                status = ResponseStatus.FAILURE;
                failInfo = FailInfo.BAD_REQUEST;
            } else {
                ret.setCertificate(certWrapper.getCertificate());
                ret.setCACert(ca.getCACertificate());
                ret.setBase64CertData(certWrapper.getBase64CertData());
                ret.setCertificateData(certWrapper.getCertificateData());
            }
            ret.setStatus(status);
            if (failInfo != null) {
                ret.setFailInfo(failInfo);
                ret.setFailText(failText);
            }
            ret.create();          
        } catch (InvalidKeyException e) {
            throw new CertificateCreateException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateCreateException(e);
        } catch (NoSuchProviderException e) {
            throw new CertificateCreateException(e);
        } catch(CertificateEncodingException e) {
            throw new CertificateCreateException(e);
        } catch (CRLException e) {
            throw new CertificateCreateException(e);
        } 

        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(IRequestMessage, CA)");
        }
        return ret;
    }

    @Override
    public CertificateResponseMessage createCertificate(final AuthenticationToken admin, final EndEntityInformation userData,
            final RequestMessage req, final Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams) throws CADoesntExistsException,
            AuthorizationDeniedException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalKeyException, IllegalNameException,
            CustomCertificateSerialNumberException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        final long updateTime = System.currentTimeMillis();
        return createCertificate(admin, userData, req, responseClass, certGenParams, updateTime);
    }


    @Override
    public CertificateResponseMessage createCertificate(final AuthenticationToken admin, final EndEntityInformation userData,
            final RequestMessage req, final Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams, final long updateTime) throws CADoesntExistsException,
            AuthorizationDeniedException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalKeyException, IllegalNameException,
            CustomCertificateSerialNumberException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(IRequestMessage)");
        }
        final CA ca;
        // First find the CA, this checks authorization and that the CA exists
        if ((userData == null) || (userData.getCAId() == 0)) {
            // If no CAid in the supplied userdata
            ca = getCAFromRequest(admin, req);
        } else {
            ca = caSession.getCA(admin, userData.getCAId());
        }

        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(IRequestMessage)");
        }
        return createCertificate(admin, userData, ca, req, responseClass, certGenParams, updateTime);
    }

    /**
     * Help Method that extracts the CA specified in the request.
     * 
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private CA getCAFromRequest(final AuthenticationToken admin, final RequestMessage req) throws CADoesntExistsException,
            AuthorizationDeniedException {
        CA ca = null;
        // See if we can get issuerDN directly from request
        if (req.getIssuerDN() != null) {
            String dn = certificateStoreSession.getCADnFromRequest(req);
            ca = caSession.getCA(admin, dn.hashCode());
            if (log.isDebugEnabled()) {
                log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
            }
        } else {
            throw new CADoesntExistsException(intres.getLocalizedMessage("createcert.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
        }

        if (ca.getStatus() != CAConstants.CA_ACTIVE) {
            final String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
            throw new EJBException(msg);
        }
        return ca;
    }
    
    @Override
    public CertificateDataWrapper createCertificate(final AuthenticationToken admin, final EndEntityInformation endEntityInformation, final CA ca, final RequestMessage request,
            final PublicKey pk, final int keyusage, final Date notBefore, final Date notAfter, final Extensions extensions, final String sequence,
            CertificateGenerationParams certGenParams, final long updateTime) throws AuthorizationDeniedException, IllegalNameException, CustomCertificateSerialNumberException,
            CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException,
            IllegalKeyException, CertificateExtensionException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)");
        }
        
        // Even though CA is passed as an argument to this method, we do check authorization on that.
        // To make sure we properly log authorization checks needed to issue a cert.
        // We need to check that admin have rights to create certificates, and have access to the CA
        if (!accessSession.isAuthorized(admin, StandardRules.CREATECERT.resource(), StandardRules.CAACCESS.resource() + ca.getCAId())) {
            final String msg = intres.getLocalizedMessage("createcert.notauthorized", admin.toString(), ca.getCAId());
            throw new AuthorizationDeniedException(msg);
        }

        // Audit log that we received the request
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("subjectdn", endEntityInformation.getDN());
        details.put("requestX500name", (request == null || request.getRequestX500Name() == null) ? "null" : request.getRequestX500Name().toString());
        details.put("certprofile", endEntityInformation.getCertificateProfileId());
        details.put("keyusage", keyusage);
        details.put("notbefore", notBefore);
        details.put("notafter", notAfter);
        details.put("sequence", sequence);
        details.put("publickey", new String(Base64.encode(pk.getEncoded(), false)));
        logSession.log(EventTypes.CERT_REQUEST, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(),
                String.valueOf(ca.getCAId()), null, endEntityInformation.getUsername(), details);

        // Set up audit logging of CT pre-certificate
        addCTLoggingCallback(certGenParams, admin.toString());

        try {
            CertificateDataWrapper result = null;
            // If the user is of type USER_INVALID, it cannot have any other type (in the mask)
            if (endEntityInformation.getType().isType(EndEntityTypes.INVALID)) {
                final String msg = intres.getLocalizedMessage("createcert.usertypeinvalid", endEntityInformation.getUsername());
                throw new CertificateCreateException(msg);
            }
            final Certificate cacert = ca.getCACertificate();
            final String caSubjectDN = CertTools.getSubjectDN(cacert);
            assertSubjectEnforcements(ca, caSubjectDN, endEntityInformation, pk);
            // Retrieve the certificate profile this user should have, checking for authorization to the profile
            final int certProfileId = endEntityInformation.getCertificateProfileId();
            final CertificateProfile certProfile = getCertificateProfile(certProfileId, ca.getCAId());

            // Check that the request public key fulfills policy
            verifyKey(pk, certProfile);

            // Below we have a small loop if it would happen that we generate the same serial number twice
            // If using only 4 byte serial numbers this do happen once in a while
            Certificate cert = null;
            String cafingerprint = null;
            String serialNo = "unknown";
            final boolean useCustomSN;
            {
                final ExtendedInformation ei = endEntityInformation.getExtendedinformation();
                useCustomSN = ei != null && ei.certificateSerialNumber() != null;
            }
            final int maxRetrys;
            if (useCustomSN) {
                if (ca.isUseCertificateStorage() && !isUniqueCertificateSerialNumberIndex()) {
                    final String msg = intres.getLocalizedMessage("createcert.not_unique_certserialnumberindex");
                    log.error(msg);
                    throw new CustomCertificateSerialNumberException(msg);
                }
                if (!certProfile.getAllowCertSerialNumberOverride()) {
                    final String msg = intres
                            .getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override", Integer.valueOf(certProfileId));
                    log.info(msg);
                    throw new CustomCertificateSerialNumberException(msg);
                }
                maxRetrys = 1;
            } else {
                maxRetrys = 5;
            }
            
            // Before storing the new certificate, check if single active certificate constraint is active, and if so let's revoke all active and unexpired certificates
            if (certProfile.isSingleActiveCertificateConstraint()) {
                for (Certificate certificate : certificateStoreSession.findCertificatesBySubjectAndIssuer(endEntityInformation.getCertificateDN(),
                        caSubjectDN, true)) {
                    //Authorization to the CA was already checked at the head of this method, so no need to do so now
                    certificateStoreSession.setRevokeStatusNoAuth(admin, certificate, new Date(), RevokedCertInfo.REVOCATION_REASON_SUPERSEDED, endEntityInformation.getDN());
                }
            }
            
            CertificateSerialNumberException storeEx = null; // this will not be null if stored == false after the below passage
            for (int retrycounter = 0; retrycounter < maxRetrys; retrycounter++) {
                final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                if (cryptoToken==null) {
                    final String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getCAId());
                    log.info(msg);
                    CryptoTokenOfflineException exception = new CryptoTokenOfflineException("CA's CryptoToken not found.");
                    auditFailure(admin, exception, exception.getMessage(), "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
                    throw exception;
                }
                cert = ca.generateCertificate(cryptoToken, endEntityInformation, request, pk, keyusage, notBefore, notAfter, certProfile, extensions, sequence, certGenParams);
                serialNo = CertTools.getSerialNumberAsString(cert);
                cafingerprint = CertTools.getFingerprintAsString(cacert);
                // Store certificate in the database, if this CA is configured to do so.
                if (!ca.isUseCertificateStorage()) {
                    result = new CertificateDataWrapper(cert, null, null);
                    break; // We have our cert and we don't need to store it.. Move on..
                }
                try {
                    // Remember for CVC serialNo can be alphanumeric, so we can't just try to decode that using normal Java means (BigInteger.valueOf)...
                    assertSerialNumberForIssuerOk(ca, caSubjectDN, CertTools.getSerialNumber(cert));
                    // Tag is reserved for future use, currently only null
                    final String tag = null;
                    // Authorization was already checked by since this is a private method, the CA parameter should
                    // not be possible to get without authorization
                    result = certificateStoreSession.storeCertificateNoAuth(admin, cert, endEntityInformation.getUsername(), cafingerprint, CertificateConstants.CERT_ACTIVE,
                            certProfile.getType(), certProfileId, tag, updateTime);
                    storeEx = null;
                    break;
                } catch (CertificateSerialNumberException e) {
                    // If we have created a unique index on (issuerDN,serialNumber) on table CertificateData we can
                    // get a CreateException here if we would happen to generate a certificate with the same serialNumber
                    // as one already existing certificate.
                    if (retrycounter + 1 < maxRetrys) {
                        log.info("Can not store certificate with serNo (" + serialNo + "), will retry (retrycounter=" + retrycounter
                                + ") with a new certificate with new serialNo: " + e.getMessage());
                    }
                    storeEx = e;
                }
            }
            if (storeEx != null) {
                if (useCustomSN) {
                    final String msg = intres.getLocalizedMessage("createcert.cert_serial_number_already_in_database", serialNo);
                    log.info(msg);
                    throw new CustomCertificateSerialNumberException(msg);
                }
                log.error("Can not store certificate in database in 5 tries, aborting: ", storeEx);
                throw storeEx;
            }

            // Finally we check if this certificate should not be issued as active, but revoked directly upon issuance
            int revreason = RevokedCertInfo.NOT_REVOKED;
            ExtendedInformation ei = endEntityInformation.getExtendedinformation();
            if (ei != null) {
            	revreason = ei.getIssuanceRevocationReason();
            	if (revreason != RevokedCertInfo.NOT_REVOKED) {
                    // If we don't store the certificate in the database, we wont support revocation/reactivation so issuing revoked certificates would be
                    // really strange.
                    if (ca.isUseCertificateStorage()) {
                        certificateStoreSession.setRevokeStatusNoAuth(admin, cert, new Date(), revreason, endEntityInformation.getDN());
                    } else {
                        log.warn("CA configured to revoke issued certificates directly, but not to store issued the certificates. Revocation will be ignored. Please verify your configuration.");
                    }
            	}
            }
            if (log.isDebugEnabled()) {
                log.debug("Generated certificate with SerialNumber '" + serialNo + "' for user '" + endEntityInformation.getUsername() + "', with revocation reason="
                        + revreason);
                log.debug(cert.toString());
            }
            
            // Audit log that we issued the certificate
            final Map<String, Object> issuedetails = new LinkedHashMap<String, Object>();
            issuedetails.put("subjectdn", endEntityInformation.getDN());
            issuedetails.put("certprofile", endEntityInformation.getCertificateProfileId());
            issuedetails.put("issuancerevocationreason", revreason);
            try {
                issuedetails.put("cert", new String(Base64.encode(cert.getEncoded(), false)));
            } catch (CertificateEncodingException e) {
                //Should not be able to happen at this point
                throw new IllegalStateException();
            }
            logSession.log(EventTypes.CERT_CREATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), serialNo, endEntityInformation.getUsername(),
            		issuedetails);

            if (log.isTraceEnabled()) {
                log.trace("<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)");
            }
            return result;
            // We need to catch and re-throw all of these exception just because we need to audit log all failures
        } catch (CustomCertificateSerialNumberException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        }  catch (AuthorizationDeniedException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        } catch (CertificateCreateException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            // Rollback
            throw e;
        } catch(CryptoTokenOfflineException e) {
            final String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getCAId());
            log.info(msg);
            auditFailure(admin, e, e.getMessage(), "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        } catch (CAOfflineException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        } catch (InvalidAlgorithmException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        } catch (IllegalValidityException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        } catch (OperatorCreationException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            // Rollback
            throw new CertificateCreateException(e);
        } catch (SignatureException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            // Rollback
            throw new CertificateCreateException(e);
        } catch (CertificateExtensionException e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X500Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), endEntityInformation.getUsername());
            throw e;
        }
        
    }

    private void addCTLoggingCallback(CertificateGenerationParams certGenParams, final String authTokenName) {
        if (certGenParams != null) {
            certGenParams.setCTAuditLogCallback(new CTAuditLogCallback() {
                @Override
                public void logPreCertSubmission(X509CA issuer, EndEntityInformation subject, X509Certificate precert, boolean success) {
                    // Mostly the same info is logged as in CertificateCreateSessionBean.createCertificate
                    final Map<String, Object> issuedetails = new LinkedHashMap<String, Object>();
                    issuedetails.put("ctprecert", true);
                    issuedetails.put("msg", intres.getLocalizedMessage(success ? "createcert.ctlogsubmissionsuccessful" : "createcert.ctlogsubmissionfailed"));
                    issuedetails.put("subjectdn", CertTools.getSubjectDN(precert));
                    issuedetails.put("certprofile", subject.getCertificateProfileId());
                    try {
                        issuedetails.put("cert", new String(Base64.encode(precert.getEncoded(), false)));
                    } catch (CertificateEncodingException e) {
                        log.warn("Could not encode cert", e);
                    }
                    logSession.log(EventTypes.CERT_CTPRECERT_SUBMISSION, success ? EventStatus.SUCCESS : EventStatus.FAILURE,
                            ModuleTypes.CERTIFICATE, ServiceTypes.CORE, authTokenName, String.valueOf(issuer.getCAId()),
                            CertTools.getSerialNumberAsString(precert), subject.getUsername(), issuedetails);
                }
            });
        }
    }

    /**
     * Happy path optimization that performs enforcement checks as a single database round trip.
     * However, if any of the checks fail we will end up with additional queries to find out what went wrong.
     * 
     * @param ca
     * @param issuerDN
     * @param endEntityInformation
     * @param publicKey
     * @throws CertificateCreateException if the certificate couldn't be created. 
     */
    private void assertSubjectEnforcements(final CA ca, final String issuerDN, final EndEntityInformation endEntityInformation, final PublicKey publicKey) throws CertificateCreateException {
        boolean enforceUniqueDistinguishedName = false;
        if (ca.isDoEnforceUniqueDistinguishedName()) {
            if (ca.isUseCertificateStorage()) {
                enforceUniqueDistinguishedName = true;
            } else {
                log.warn("CA configured to enforce unique SubjectDN, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
            }
        }
        boolean enforceUniquePublicKeys = false;
        if (ca.isDoEnforceUniquePublicKeys()) {
            if (ca.isUseCertificateStorage()) {
                enforceUniquePublicKeys = true;
            } else {
                log.warn("CA configured to enforce unique entity keys, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
            }
        }
        final String username = endEntityInformation.getUsername();
        String subjectDN = null;
        if (enforceUniqueDistinguishedName) {
            subjectDN = endEntityInformation.getCertificateDN();
        }
        byte[] subjectKeyId = null;
        if (enforceUniquePublicKeys) {
            subjectKeyId = KeyTools.createSubjectKeyId(publicKey).getKeyIdentifier();
        }
        boolean multipleCheckOk = false;
        
        // The below combined query is commented out because there is a bug in MySQL 5.5 that causes it to 
        // select bad indexes making the query slow. In MariaDB 5.5 and MySQL 5.6 it works well, so it is MySQL 5.5 specific.
        // See ECA-3309
//        if (enforceUniqueDistinguishedName && enforceUniquePublicKeys) {
//            multipleCheckOk = certificateStoreSession.isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN(issuerDN, subjectKeyId, subjectDN, username);
//        }
        
        // If one of the checks failed, we need to investigate further what went wrong
        if (!multipleCheckOk && enforceUniqueDistinguishedName) {
            final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectDN(issuerDN, subjectDN);
            if (users.size() > 0 && !users.contains(username)) {
                final String msg = intres.getLocalizedMessage("createcert.subjectdn_exists_for_another_user", username,
                        listUsers(users));
                throw new CertificateCreateException(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER, msg);
            }
        }
        if (!multipleCheckOk && enforceUniquePublicKeys) {
            final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectKeyId(issuerDN, subjectKeyId);
            if (users.size() > 0 && !users.contains(username)) {
                final String msg = intres.getLocalizedMessage("createcert.key_exists_for_another_user", username);
                log.info(msg+listUsers(users));
                throw new CertificateCreateException(ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER, msg);
            }
        }
    }

    /** When no unique index is present in the database, we still try to enforce X.509 serial number per CA uniqueness. 
     * @throws CertificateCreateException if serial number already exists in database
     */
    private void assertSerialNumberForIssuerOk(final CA ca, final String issuerDN, final BigInteger serialNumber) throws CertificateSerialNumberException {
        if (ca.getCAType()==CAInfo.CATYPE_X509 && !isUniqueCertificateSerialNumberIndex()) {
            if (certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, serialNumber)!=null) {
                final String msg = intres.getLocalizedMessage("createcert.cert_serial_number_already_in_database", serialNumber.toString());
                log.info(msg);
                throw new CertificateSerialNumberException(msg);
            }
        }
    }

    private CertificateProfile getCertificateProfile(final int certProfileId, final int caid) throws AuthorizationDeniedException {
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
        // What if certProfile == null?
        if (certProfile == null) {
            final String msg = intres.getLocalizedMessage("createcert.errorcertprofilenotfound", Integer.valueOf(certProfileId));
            throw new AuthorizationDeniedException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using certificate profile with id " + certProfileId);
        }

        // Check that CAid is among available CAs
        boolean caauthorized = false;
        for (final Integer nextInt : certProfile.getAvailableCAs()) {
            final int next = nextInt.intValue();
            if (next == caid || next == CertificateProfile.ANYCA) {
                caauthorized = true;
                break;
            }
        }
        if (!caauthorized) {
            final String msg = intres.getLocalizedMessage("createcert.errorcertprofilenotauthorized", Integer.valueOf(caid),
                    Integer.valueOf(certProfileId));
            throw new AuthorizationDeniedException(msg);
        }
        return certProfile;
    }

    /**
     * FIXME: Documentation
     * 
     * @param admin
     * @param e
     */
    private void auditFailure(final AuthenticationToken admin, final Exception e, final String extraDetails, final String tracelog, final int caid, final String username) {
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", e.getMessage());
        if (extraDetails != null) {
            details.put("details", extraDetails);
        }
        logSession.log(EventTypes.CERT_CREATION, EventStatus.FAILURE, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, username, details);
        if (log.isTraceEnabled()) {
            if (tracelog != null) {
                log.trace(tracelog);
            }
        }
    }

    /**
     * Checks that a public key sent in a request fulfills the policy in the CertificateProfile
     * 
     * @param pk PublicKey sent in request
     * @param certProfile CertificateProfile with the key policy (length restrictions)
     * @throws IllegalKeyException if the PublicKey does not fulfill policy in CertificateProfile
     */
    private void verifyKey(final PublicKey pk, final CertificateProfile certProfile) throws IllegalKeyException {
        // Verify key length that it is compliant with certificate profile
        final int keyLength = KeyTools.getKeyLength(pk);
        if (log.isDebugEnabled()) {
            log.debug("Keylength = " + keyLength);
        }
        if (keyLength == -1) {
            final String text = intres.getLocalizedMessage("createcert.unsupportedkeytype", pk.getClass().getName());
            // logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null,
            // LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
            throw new IllegalKeyException(text);
        }
        if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1)) || (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
            final String text = intres.getLocalizedMessage("createcert.illegalkeylength", Integer.valueOf(keyLength));
            // logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null,
            // LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
            throw new IllegalKeyException(text);
        }
    }

    /**
     * Small function that makes a list of users, space separated. Used for logging. Only actually displays the first 10 records, then a notice how
     * many records were not displayed
     * 
     * @param users a set of usernames to create a string of
     * @return space separated list of usernames, i.e. "'user1' 'user2' 'user3'", max 10 users
     */
    private String listUsers(final Set<String> users) {
        final StringBuilder sb = new StringBuilder();
        int bar = 0; // limit number of displayed users
        for (final String user : users) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            if (bar++ > 9) {
                sb.append("and ").append(users.size() - bar + 1).append(" users not displayed");
                break;
            }
            sb.append('\'');
            sb.append(user);
            sb.append('\'');
        }
        return sb.toString();
    }

	@Override
    public boolean isUniqueCertificateSerialNumberIndex() {
    	return certificateStoreSession.isUniqueCertificateSerialNumberIndex();
    }
}
