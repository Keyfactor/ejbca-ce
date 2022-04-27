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

package org.ejbca.core.protocol.cmp;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSession;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ra.CertificateRequestSession;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Message handler for certificate request messages in the CRMF format.
 */
public class CrmfMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(CrmfMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    /** strings for error messages defined in internal resources */
	private static final String CMP_ERRORADDUSER = "cmp.erroradduser";
	private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";

	/** Parameters used for username generation if we are using RA mode to create users */
	private final UsernameGeneratorParams usernameGenParams;
	/** Parameters used for temporary password generation */
	private final String userPwdParams;
	/** Parameter used to determine the type of protection for the response message */
	private final String responseProt;
	/** Determines if it the RA will look for requested custom certificate serial numbers, if false such data is ignored */
	private final boolean allowCustomCertSerno;
	
    private final AuthorizationSession authorizationSession;
    private final EndEntityAccessSession endEntityAccessSession;
    private final EndEntityManagementSession endEntityManagementSession;
    private final CertificateStoreSession certStoreSession;
    private final CertificateRequestSession certificateRequestSession;
    private final SignSession signSession;
    private final WebAuthenticationProviderSessionLocal authenticationProviderSession;

    /** Construct the message handler. */
    public CrmfMessageHandler(final AuthenticationToken authenticationToken, final CmpConfiguration cmpConfiguration, final String configAlias, final EjbBridgeSessionLocal ejbBridgeSession,
            CertificateRequestSessionLocal certificateRequestSession) {
        super(authenticationToken, cmpConfiguration, configAlias, ejbBridgeSession);
        this.ejbBridgeSession = ejbBridgeSession;
        this.signSession = ejbBridgeSession.getSignSession();
        this.certificateRequestSession = certificateRequestSession;
        this.endEntityAccessSession = ejbBridgeSession.getEndEntityAccessSession();
        this.certStoreSession = ejbBridgeSession.getCertificateStoreSession();
        this.authorizationSession = ejbBridgeSession.getAuthorizationSession();
        this.authenticationProviderSession = ejbBridgeSession.getWebAuthenticationProviderSession();
        this.endEntityManagementSession = ejbBridgeSession.getEndEntityManagementSession();
        
        if (this.cmpConfiguration.getRAMode(this.confAlias)) {
            // create UsernameGeneratorParams
            this.usernameGenParams = new UsernameGeneratorParams();
            this.usernameGenParams.setMode(this.cmpConfiguration.getRANameGenScheme(this.confAlias));
            this.usernameGenParams.setDNGeneratorComponent(this.cmpConfiguration.getRANameGenParams(this.confAlias));
            this.usernameGenParams.setPrefix(this.cmpConfiguration.getRANameGenPrefix(this.confAlias));
            this.usernameGenParams.setPostfix(this.cmpConfiguration.getRANameGenPostfix(this.confAlias));
            this.userPwdParams =  this.cmpConfiguration.getRAPwdGenParams(this.confAlias);
            this.allowCustomCertSerno = this.cmpConfiguration.getAllowRACustomSerno(this.confAlias);
            this.responseProt = this.cmpConfiguration.getResponseProtection(this.confAlias);
            if (LOG.isDebugEnabled()) {
                LOG.debug("cmp.operationmode=ra");
                LOG.debug("cmp.ra.allowcustomcertserno="+allowCustomCertSerno);
                LOG.debug("cmp.ra.passwordgenparams="+userPwdParams);
                LOG.debug("cmp.responseprotection="+responseProt);
            }
        } else {
            this.usernameGenParams = null;
            this.userPwdParams = "random";
            this.responseProt = null;
            this.allowCustomCertSerno = false;
        }        
    }
    
    /**
     * Gets the end entity with that subject DN either 
     * - by extracting the username by a DN component ({@link CmpConfiguration#getExtractUsernameComponent(String)}
     * - or by matching its DN exactly.
     * 
     * @param dn the end entities DN (must match exactly).
     * @return the end entity that either has a matching username extracted from the DN, or a subjectDN that matches the dn exactly, or null if no user found.
     * @throws AuthorizationDeniedException if authorization was denied.
     */
    private EndEntityInformation getEndEntityFromCertReqRequest(final String dn) throws AuthorizationDeniedException {
        String username = getUsernameByDnComponent(dn);
        EndEntityInformation result = null;
        if (StringUtils.isNotEmpty(username)) {
            result = endEntityAccessSession.findUser(admin, username);            
        }
        if (result == null) {
            // ECA-6435 Overwrite the EE DN with the request DN fails here, independent from CertificateProile.setAllowDnOverride, 
            // if the request DN does not contain the VCs DN component to extract, but fails anyway (see VendorAuthenticationTest.test3GPPModeWithUserFromVendorCertUIDOrRequestFullDN()).
            result = getEndEntityByDn(dn);
        }
        return result;
    }
    
    @Override
	public ResponseMessage handleMessage(final BaseCmpMessage cmpRequestMessage, final boolean authenticated) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		ResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq;
			if (cmpRequestMessage instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) cmpRequestMessage;
                // If message was signed, use the same signature alg in response
                if(crmfreq.getHeader().getProtectionAlg() != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("CRMF request message header has protection alg: " + crmfreq.getHeader().getProtectionAlg().getAlgorithm().getId());
                    }
                    crmfreq.setPreferredDigestAlg(AlgorithmTools.getDigestFromSigAlg(crmfreq.getHeader().getProtectionAlg().getAlgorithm().getId()));
                } else if (LOG.isDebugEnabled()) {
                    LOG.debug("CRMF request message header has no protection alg, using default alg in response.");
                }

                // If we have usernameGeneratorParams we want to generate usernames automagically for requests
                // If we are not in RA mode, usernameGeneratorParams will be null
				if (usernameGenParams != null) {
					resp = handleRaMessage(crmfreq, authenticated);
				} else {
					// Try to find the user that is the subject for the request
					// if extractUsernameComponent is null, we have to find the user from the DN
					// if not empty the message will find the username itself, in the getUsername method
					final String dn = crmfreq.getSubjectDN();
					final EndEntityInformation endEntityInformation = getEndEntityFromCertReqRequest(crmfreq.getSubjectDN());
					if (endEntityInformation != null) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Found username: "+endEntityInformation.getUsername());
						}
						final String username = endEntityInformation.getUsername();
						crmfreq.setUsername(username);
						final VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(null, this.confAlias, admin, caSession, 
						                endEntityAccessSession, certStoreSession, authorizationSession, endEntityProfileSession, certificateProfileSession,
						                authenticationProviderSession, endEntityManagementSession, this.cmpConfiguration);
						final ICMPAuthenticationModule authenticationModule = messageVerifyer.getUsedAuthenticationModule(crmfreq.getPKIMessage(), username,  authenticated);
						if(authenticationModule == null) {
						    String errmsg = messageVerifyer.getErrorMessage();
						    LOG.info(errmsg);
						    return CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.BAD_REQUEST, errmsg);
						}
						
						crmfreq.setPassword(authenticationModule.getAuthenticationString());
		                // Do we have a public key in the request? If not we may be trying to do server generated keys
		                enrichWithServerGeneratedKeyOrThrow(crmfreq, endEntityInformation.getCertificateProfileId());
		                resp = signSession.createCertificate(admin, crmfreq, CmpResponseMessage.class, endEntityInformation);
					} else {
						final String errMsg = INTRES.getLocalizedMessage("cmp.infonouserfordn", dn);
						LOG.info(errMsg);						
		                // If we didn't find the entity return error message
		                final String failText = INTRES.getLocalizedMessage("ra.wrongusernameorpassword");
		                LOG.info(failText);
                        resp = signSession.createRequestFailedResponse(admin, crmfreq, CmpResponseMessage.class,
                                FailInfo.INCORRECT_DATA, failText);
					}
				}
			} else {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errornocmrfreq");
				LOG.error(errMsg);
			}
			
			if (resp == null) {
                final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
                LOG.error(errMsg);
                throw new IllegalStateException(errMsg);
			}
		} catch (NoSuchProviderException e) {
		    // Thrown checking for the public key in the request, if this is thrown there is something missing in the system 
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.error(errMsg, e);    
            resp = CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.SYSTEM_UNAVAILABLE, e.getMessage());
		} catch (AuthorizationDeniedException | AuthLoginException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e);	
			resp = CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.NOT_AUTHORIZED, e.getMessage());
		} catch (CADoesntExistsException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it	
			resp = CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.WRONG_AUTHORITY, e.getMessage());
		} catch (SignRequestSignatureException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it
			resp = CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.BAD_POP, e.getMessage());
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | CesecoreException | EjbcaException | CertificateExtensionException e) {
            // Thrown checking for the public key in the request, if these are thrown there is something wrong with the key in the request
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e); // info because this is something we should expect and we handle it
            resp = CmpMessageHelper.createUnprotectedErrorMessage(cmpRequestMessage, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (EJBException e) {
			// Fatal error
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
			LOG.error(errMsg, e);			
			resp = null;
		}
        if (LOG.isTraceEnabled()) {
			LOG.trace("<handleMessage");
		}
		return resp;
	}

	/** Method that takes care of RA mode operations, i.e. when the message is authenticated with a common secret using password based encryption (pbe).
	 * This method will verify the pbe and if ok  will automatically create/edit a user and issue the certificate. In RA mode we assume that the RA knows what it is doing.
	 * 
	 * @param crmfreq
	 * @param authenticated if the CMP message has already been authenticated in another way or not
	 * @return IResponseMessage that can be sent back to the client
	 * @throws AuthorizationDeniedException
	 * @throws EjbcaException
	 * @throws CesecoreException 
	 */
	private ResponseMessage handleRaMessage(final CrmfRequestMessage crmfreq, boolean authenticated) throws AuthorizationDeniedException, EjbcaException, CesecoreException {
        final int eeProfileId;        // The endEntityProfile to be used when adding users in RA mode.
        final String certProfileName;  // The certificate profile to use when adding users in RA mode.
        final int certProfileId;
	    final int requestId = crmfreq.getRequestId();
        final int requestType = crmfreq.getRequestType();
        // Try to find a HMAC/SHA1 protection key
        final String keyId = CmpMessageHelper.getStringFromOctets(crmfreq.getHeader().getSenderKID());
        int caId = 0; // The CA to user when adding users in RA mode
        try {
            eeProfileId = getUsedEndEntityProfileId(keyId);
            caId = getUsedCaId(keyId, eeProfileId);
            certProfileName = getUsedCertProfileName(keyId, eeProfileId);
            certProfileId = getUsedCertProfileId(certProfileName);
        } catch (CADoesntExistsException e) {
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
            return CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.INCORRECT_DATA, e.getMessage(), requestId, requestType, null, keyId, this.responseProt);
        }  catch (NotFoundException | EndEntityProfileNotFoundException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);
            // In case an EE profile or a cert profiles, or a CA can not be found, this is a bad configuration or database is down. 
            // In either case the system is unavailable due to CMP server, so client should try again at some later point
            return CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.SYSTEM_UNAVAILABLE, e.getMessage(), requestId, requestType, null, keyId, this.responseProt);           
        }

        ResponseMessage resp;
        //Check the request's authenticity
        X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfoInternal(caId, null, true);
        final VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(cainfo, this.confAlias, admin, caSession, 
                endEntityAccessSession, certStoreSession, authorizationSession, endEntityProfileSession, certificateProfileSession,
                authenticationProviderSession, endEntityManagementSession, this.cmpConfiguration);
        ICMPAuthenticationModule authenticationModule = messageVerifyer.getUsedAuthenticationModule(crmfreq.getPKIMessage(),  null,  authenticated);
        if (authenticationModule == null) {
            String errmsg = messageVerifyer.getErrorMessage();
            LOG.info(errmsg);
            return CmpMessageHelper.createUnprotectedErrorMessage(crmfreq, FailInfo.BAD_REQUEST, errmsg);
        }        
        // Create a username and password and register the new user in EJBCA
        final UsernameGenerator gen = UsernameGenerator.getInstance(this.usernameGenParams);      
        final RequestMessage req;
        //Retrieve the value from the CA configuration firsthand, then check the legacy CMP value if not available
        
        @SuppressWarnings("deprecation")
        String preProcessorClass = cmpConfiguration.getCertReqHandlerClass(this.confAlias);
        //Only run if value hasn't been set in CAInfo, which should be done during the 7.4.0 upgrade
        if (!StringUtils.isEmpty(preProcessorClass) && StringUtils.isEmpty(cainfo.getRequestPreProcessor())) {
            try {
                ExtendedUserDataHandler extendedUserDataHandler = (ExtendedUserDataHandler) Class.forName(preProcessorClass).newInstance();
                req = extendedUserDataHandler.processRequestMessage(crmfreq, certProfileName);
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                throw new IllegalStateException("Request Preprocessor implementation " + preProcessorClass + " could not be instansiated.");
            }
        } else {
            req = crmfreq;
        }
        // Don't convert this DN to an ordered EJBCA DN string with CertTools.stringToBCDNString because we don't want double escaping of some characters
        final X500Name dnname = req.getRequestX500Name();
        if (dnname == null) {
            final String nullMsg = "Request DN Name can not be null";
            if (LOG.isDebugEnabled()) {
                LOG.debug(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, nullMsg));
            }
            return CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.INCORRECT_DATA, nullMsg, requestId, requestType, null, keyId,
                    this.responseProt);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Creating username from base dn: " + dnname.toString());
        }
        final String username = StringTools.stripUsername(gen.generateUsername(dnname.toString()));
        final String pwd;
        if (StringUtils.equals(authenticationModule.getName(), CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
            pwd = authenticationModule.getAuthenticationString();
        } else if (StringUtils.equals(authenticationModule.getName(), CmpConfiguration.AUTHMODULE_HMAC)) {
            if (StringUtils.equals(this.userPwdParams, "random")) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Setting 12 char random user password.");
                }
                final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
                pwd = pwdgen.getNewPassword(12, 12);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Setting fixed user password from config.");
                }
                pwd = this.userPwdParams;
            }
        } else {
            //This should not run since an error would have occurred earlier if the authentication module was unknown 
            final String errMsg = "Unknown authentication module.";
            LOG.error(errMsg);
            return CmpMessageHelper.createUnprotectedErrorMessage(crmfreq, FailInfo.BAD_MESSAGE_CHECK, errMsg);
        }
        // AltNames may be in the request template
        final String altNames = req.getRequestAltNames();
        final List<String> emails = CertTools.getEmailFromDN(altNames);
        emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
        // Use rfc822name or first SubjectDN email address as user email address if available
        final String email = emails.isEmpty() ? null : emails.get(0);
        ExtendedInformation ei = null;
        if (this.allowCustomCertSerno) {
            // Don't even try to parse out the field if it is not allowed
            final BigInteger customCertSerno = crmfreq.getSubjectCertSerialNo();
            if (customCertSerno != null) {
                // If we have a custom certificate serial number in the request, we will pass it on to the UserData object
                ei = new ExtendedInformation();
                ei.setCertificateSerialNumber(customCertSerno);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Custom certificate serial number: " + customCertSerno.toString(16));
                }
            }
        }
        final EndEntityInformation userdata = new EndEntityInformation(username, dnname.toString(), caId, altNames, email,
                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId, null, null,
                SecConst.TOKEN_SOFT_BROWSERGEN, ei);
        userdata.setPassword(pwd);
        // Set so we have the right params in the call to processCertReq. 
        // Username and pwd in the EndEntityInformation and the IRequestMessage must match
        crmfreq.setUsername(username);
        crmfreq.setPassword(pwd);
        // Set all protection parameters
        CmpPbeVerifyer verifyer = null;
        if (StringUtils.equals(authenticationModule.getName(), CmpConfiguration.AUTHMODULE_HMAC)) {
            final HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
            verifyer = hmacmodule.getCmpPbeVerifyer();
            final String pbeDigestAlg = verifyer.getOwfOid();
            final String pbeMacAlg = verifyer.getMacOid();
            final int pbeIterationCount = verifyer.getIterationCount();
            final String raSecret = verifyer.getLastUsedRaSecret();
            if (LOG.isDebugEnabled()) {
                LOG.debug("responseProt=" + this.responseProt + ", pbeDigestAlg=" + pbeDigestAlg + ", pbeMacAlg=" + pbeMacAlg + ", keyId=" + keyId
                        + ", raSecret=" + (raSecret == null ? "null" : "not null"));
            }

            if (StringUtils.equals(this.responseProt, "pbe")) {
                crmfreq.setPbeParameters(keyId, raSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
            }
        }
        try {
            // Do we have a public key in the request? If not we may be trying to do server generated keys
            enrichWithServerGeneratedKeyOrThrow((ICrmfRequestMessage) req, certProfileId);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Creating new request with eeProfileId '" + eeProfileId + "', certProfileId '" + certProfileId + "', caId '" + caId
                        + "'");
            }
            // If it was a certificate authenticated admin, we want to use this admin token to pass down core layers which will make 
            // authorization checks on it
            final AuthenticationToken adminForEjb;
            if (authenticationModule.getAuthenticationToken() != null) {
                adminForEjb = authenticationModule.getAuthenticationToken();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using admin from AuthenticationModule to call EJB. AuthModule=" + authenticationModule.getName() + ", admin: " + adminForEjb.toString());
                }
            } else {
                adminForEjb = this.admin;    
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Using AlwaysAllow admin to call EJB, admin: " + adminForEjb.toString());
                }               
            }
            try {
                resp = this.certificateRequestSession.processCertReq(adminForEjb, userdata, req, CmpResponseMessage.class);
            } catch (EndEntityExistsException e) {
                final String updateMsg = INTRES.getLocalizedMessage("cmp.erroradduserupdate", username);
                LOG.info(updateMsg);
                // Try again
                resp = this.certificateRequestSession.processCertReq(adminForEjb, userdata, req, CmpResponseMessage.class);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            // Thrown checking for the public key in the request, if these are thrown there is something wrong with the key in the request 
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, username), e);
            resp = CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.BAD_REQUEST, e.getMessage(), requestId, requestType, null, keyId,
                    this.responseProt);
        } catch (NoSuchProviderException e) {
            // Thrown checking for the public key in the request, if this is thrown there is something missing in the system 
            LOG.error(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, username), e);
            resp = CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.SYSTEM_UNAVAILABLE, e.getMessage(), requestId, requestType, null, keyId,
                    this.responseProt);
        } catch (EndEntityProfileValidationException e) {
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
            resp = CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.INCORRECT_DATA, e.getMessage(), requestId, requestType, verifyer, keyId,
                    this.responseProt);
        } catch (ApprovalException | EndEntityExistsException e) {
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
            resp = CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.NOT_AUTHORIZED, e.getMessage(), requestId, requestType, verifyer, keyId,
                    this.responseProt);
        } catch (CertificateExtensionException e) {
            LOG.info(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
            resp = CmpMessageHelper.createErrorMessage(crmfreq, FailInfo.BAD_REQUEST, e.getMessage(), requestId, requestType, verifyer, keyId,
                    this.responseProt);
        }
		return resp;
	}
	
	private void enrichWithServerGeneratedKeyOrThrow(final ICrmfRequestMessage req, final int certProfileID) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
	    SubjectPublicKeyInfo pkInfo = req.getRequestSubjectPublicKeyInfo();
	    
        // To trigger server generated keys, subjectPublicKeyInfo key could be null, but subjectPublicKeyInfo could also still be there
        // with an AlgorithmIdentifier followed by a zero-length BIT STRING (RFC4210 Appendix D.4)
	    if ( pkInfo == null || (pkInfo.getAlgorithm() != null && pkInfo.getPublicKeyData() != null && pkInfo.getPublicKeyData().getBytes().length == 0) ) {
	        if (LOG.isDebugEnabled()) {
	            LOG.debug("CRMF requests does not contain a request public key.");
	            if (pkInfo != null) {
	                LOG.debug("CRMF requests contains a SubjectPublicKeyInfo without key bits and with algorithmId "+pkInfo.getAlgorithm().getAlgorithm().getId());                
	            }
	        }
	        // Trying to request server generated keys? See if this is allowed, and then try to figure out key generation parameters
	        if (!this.cmpConfiguration.getAllowServerGeneratedKeys(this.confAlias)) {
                // Not possible to server generate key when there is no key to encrypt the response with
                throw new InvalidKeyException("Server generated keys not allowed");	            
	        }

	        // Only allow server generated keys if we have a key to encrypt the response with
	        // Even though theoretically possible, we only support RSA key transport protection/wrapping
            if (req.getProtocolEncrKey() == null || !req.getProtocolEncrKey().getAlgorithm().equals("RSA")) {
                // Not possible to server generate key when there is no key to encrypt the response with
                throw new InvalidKeyException("Request public key can not be empty without providing a suitable protocolEncrKey (RSA)");
            } else {
                LOG.debug("Found id_regCtrl_protocolEncrKey with an RSA key in request, clear to generate keys.");
            }

            KeyPair keys;
            // 2. If not, get key generation parameters from the certificate profile
            final CertificateProfile profile = certificateProfileSession.getCertificateProfile(certProfileID);
            if (profile == null) {
                final String msg = "No certificate profile to get key specification for server generated keys";
                LOG.debug(msg);
                throw new InvalidKeyException(msg);
            }
            List<String> algs = profile.getAvailableKeyAlgorithmsAsList();
            List<String> curves = profile.getAvailableEcCurvesAsList();
            if (pkInfo != null) {
                // 1. Does the client specify algorithm OID in the request?
                // If we come here we already know that there is an AlgorithmIdentifier, but no public key bits
                AlgorithmIdentifier algId = pkInfo.getAlgorithm();
                if (PKCSObjectIdentifiers.rsaEncryption.equals(algId.getAlgorithm())) {
                    if (!algs.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
                        final String msg = "RSA key generation requested, but certificate profile specified does not allow RSA";
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(msg+": "+certProfileID+": "+algs);
                        }
                        throw new InvalidKeyException(msg);                        
                    }
                    LOG.debug("RSA algorithm found in SubjectPublicKeyInfo, using as server key generation alg.");
                    algs.clear();
                    algs.add(AlgorithmConstants.KEYALGORITHM_RSA);
                } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(algId.getAlgorithm())) {
                    if (!algs.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                        final String msg = "ECDSA key generation requested, but certificate profile specified does not allow ECDSA";
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(msg+": "+certProfileID+": "+algs);
                        }
                        throw new InvalidKeyException(msg);                        
                    }
                    LOG.debug("ECDSA algorithm found in SubjectPublicKeyInfo, using as server key generation alg.");
                    algs.clear();
                    algs.add(AlgorithmConstants.KEYALGORITHM_ECDSA);
                    // Looking for key gen parameters for EC
                    if (pkInfo.getAlgorithm().getParameters() == null) {
                        final String msg = "ECDSA key generation requested, but no key parameters included";
                        throw new InvalidKeyException(msg);                                                
                    } else {
                        try {
                            X962Parameters params = X962Parameters.getInstance(pkInfo.getAlgorithm().getParameters());
                            if (params.isImplicitlyCA()) {
                                LOG.debug("ECDSA key generation parameters is implicitlyCA, will try to use certificate profile parameters.");
                            } else if (params.isNamedCurve()) {
                                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
                                final String curveName = ECNamedCurveTable.getName(oid);
                                if (curveName == null) {
                                    final String msg = "ECDSA key generation requested, but X962Parameters is none of the supported named curves: "+oid.getId();
                                    LOG.debug(msg);
                                    throw new InvalidKeyException(msg);                                                                                                                                                
                                }
                                // Check that this curve is allowed in the Certificate Profile, 
                                // compare oids, since names have many aliases...and first choice alias can change between different BC versions
                                boolean found = false;
                                for (String curve : curves) {
                                    final ASN1ObjectIdentifier id = ECNamedCurveTable.getOID(curve);
                                    if (id != null && oid.equals(id)) {
                                        found = true;
                                    }
                                }
                                if (!found) {
                                    final String msg = "ECDSA key generation requested, but X962Parameters curve is none of the allowed named curves: "+curveName;
                                    LOG.debug(msg);
                                    throw new InvalidKeyException(msg);                                                                                                                                                                                    
                                }
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("ECDSA key generation parameters is namedCurve, will try to generate key with named curve "+oid.getId()+", "+curveName);
                                }
                                curves.clear();
                                curves.add(curveName);
                            } else {
                                final String msg = "ECDSA key generation requested, but X962Parameters is none of the supported options implicitlyCA or namedCurve";
                                throw new InvalidKeyException(msg);                                                                                                            
                            }
                        } catch (IllegalArgumentException e) {
                            final String msg = "ECDSA key generation requested, but X962Parameters can not be decoded";
                            throw new InvalidKeyException(msg, e);                                                                            
                        }
                    }
                } else {
                    final String msg = "Server key generation requested, but SubjectPublicKeyInfo specifies unsupported algorithm "+algId.getAlgorithm().getId();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(msg+": "+certProfileID+": "+algs);
                    }
                    throw new InvalidKeyException(msg);                    
                }
            } // pkInfo != null
            
            if (algs.size() > 1) {
                final String msg = "Certificate profile specified more than one key algoritm, not possible to server generate keys";
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msg+": "+certProfileID+": "+algs);
                }
                throw new InvalidKeyException(msg);
            }
            if (AlgorithmConstants.KEYALGORITHM_RSA.equals(algs.get(0))) {
                int[] sizes = profile.getAvailableBitLengths();
                if (sizes == null || sizes.length > 1) {
                    final String msg = "Certificate profile specified more than one key size, not possible to server generate keys";
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(msg+": "+certProfileID+": " + Arrays.toString(sizes));
                    }
                    throw new InvalidKeyException(msg);                        
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generating server generated keypair RSA "+sizes[0]);
                }
                keys = KeyTools.genKeys(String.valueOf(sizes[0]), AlgorithmConstants.KEYALGORITHM_RSA);                    
            } else if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(algs.get(0))) {
                if (curves.size() > 1) {
                    final String msg = "Certificate profile specified more than one EC curve, not possible to server generate keys";
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(msg+": "+certProfileID+": "+curves);
                    }
                    throw new InvalidKeyException(msg);                        
                }
                keys = KeyTools.genKeys(curves.get(0), AlgorithmConstants.KEYALGORITHM_ECDSA);  
                
            } else {
                final String msg = "Certificate profile an algorithm not supported for server generated keys";
                LOG.debug(msg);
                throw new InvalidKeyException(msg);                    
            }
            // We finally got our keys if we get all the way down here
            req.setServerGenKeyPair(keys);
	    } else {
	        LOG.debug("CRMF requests contains a request public key.");
	    }

	}
    
    /**
     * Gets the end entity by the its subject DN.
     * @param dn the subject DN.
     * @return the end entity with this DN.
     * @throws AuthorizationDeniedException if authorization was denied.
     */
    private EndEntityInformation getEndEntityByDn(String dn) throws AuthorizationDeniedException {
	    EndEntityInformation endEntityInformation = null;
	    if (LOG.isDebugEnabled()) {
	        LOG.debug("looking for user with dn: "+dn);
	    }
	    List<EndEntityInformation> endEntityInformations = endEntityAccessSession.findUserBySubjectDN(admin, dn);
	    if (!endEntityInformations.isEmpty()) {
	        endEntityInformation = endEntityInformations.get(0);
	        if (endEntityInformations.size() > 1) {
	            LOG.warn("Multiple end entities with subject DN " + dn + " were found. This may lead to unexpected behavior.");
	        }
	    }
        return endEntityInformation;
	}

    /**
     * Gets the username by the DN component specified in the CMP configuration 'extract username component' 
     * and adds the RA name generation prefix and postfix.
     * 
     * @param dn the DN.
     * @return the username with RA name generation prefix and postfix.
     */
    private String getUsernameByDnComponent(String dn) {
        final String usernameComp = this.cmpConfiguration.getExtractUsernameComponent(this.confAlias);
        if (LOG.isDebugEnabled()) {
            LOG.debug("extractUsernameComponent: "+usernameComp);
        }
        if(StringUtils.isNotEmpty(usernameComp)) {
            String username = CertTools.getPartFromDN(dn,usernameComp);
            String fix = cmpConfiguration.getRANameGenPrefix(this.confAlias);
            if (StringUtils.isNotBlank(fix)) {
                LOG.info("Preceded RA name prefix '" + fix + "' to username '" + username + "' in CMP vendor mode.");
                username = fix + username;
            }
            fix = cmpConfiguration.getRANameGenPostfix(this.confAlias);
            if (StringUtils.isNotBlank( cmpConfiguration.getRANameGenPostfix(this.confAlias))) {
                LOG.info("Attached RA name postfix '" + fix + "' to username '" + username + "' in CMP vendor mode.");
                username += fix;
            }
            return username;
        }    
        return null;
    }
}
