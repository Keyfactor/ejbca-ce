/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

import javax.ejb.EJBException;
import javax.persistence.PersistenceException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ra.CertificateRequestSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ExtendedUserDataHandler;
import org.ejbca.core.protocol.ExtendedUserDataHandler.HandlerException;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id$
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
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private final String raAuthSecret;
	/** Parameter used to determine the type of protection for the response message */
	private final String responseProt;
	/** Determines if it the RA will look for requested custom certificate serial numbers, if false such data is ignored */
	private final boolean allowCustomCertSerno;
	/** Extra pre-processing of requests */ 
	private final ExtendedUserDataHandler extendedUserDataHandler;
	
	private final SignSession signSession;
	private final UserAdminSession userAdminSession;
	private final CertificateRequestSession certificateRequestSession;
	
	/**
	 * Used only by unit test.
	 */
	public CrmfMessageHandler () {
		super();
		this.usernameGenParams = null;
		this.userPwdParams = "random";
		this.raAuthSecret = null;
		this.responseProt = null;
		this.allowCustomCertSerno = false;
		this.signSession =null;
		this.userAdminSession = null;
		this.certificateRequestSession = null;
		this.extendedUserDataHandler = null;
	}
	
	/**
	 * Construct the message handler.
	 * @param admin
	 * @param caSession
	 * @param certificateProfileSession
	 * @param certificateRequestSession
	 * @param endEntityProfileSession
	 * @param signSession
	 * @param userAdminSession
	 */
	public CrmfMessageHandler(final AuthenticationToken admin, CaSession caSession, CertificateProfileSession certificateProfileSession, CertificateRequestSession certificateRequestSession,
			EndEntityProfileSession endEntityProfileSession, SignSession signSession, UserAdminSession userAdminSession) {
		super(admin, caSession, endEntityProfileSession, certificateProfileSession);
		// Get EJB beans, we can not use local beans here because the TCP listener does not work with that
		this.signSession = signSession;
		this.userAdminSession = userAdminSession;
		this.certificateRequestSession = certificateRequestSession;

		if (CmpConfiguration.getRAOperationMode()) {
			// create UsernameGeneratorParams
			this.usernameGenParams = new UsernameGeneratorParams();
			this.usernameGenParams.setMode(CmpConfiguration.getRANameGenerationScheme());
			this.usernameGenParams.setDNGeneratorComponent(CmpConfiguration.getRANameGenerationParameters());
			this.usernameGenParams.setPrefix(CmpConfiguration.getRANameGenerationPrefix());
			this.usernameGenParams.setPostfix(CmpConfiguration.getRANameGenerationPostfix());
			this.userPwdParams =  CmpConfiguration.getUserPasswordParams();
			this.raAuthSecret = CmpConfiguration.getRAAuthenticationSecret();
			this.allowCustomCertSerno = CmpConfiguration.getRAAllowCustomCertSerno();
			this.responseProt = CmpConfiguration.getResponseProtection();
			if (LOG.isDebugEnabled()) {
				LOG.debug("cmp.operationmode=ra");
				LOG.debug("cmp.ra.allowcustomcertserno="+allowCustomCertSerno);
				LOG.debug("cmp.ra.passwordgenparams="+userPwdParams);
				LOG.debug("cmp.responseprotection="+responseProt);
			}
		} else {
			this.usernameGenParams = null;
			this.userPwdParams = "random";
			this.raAuthSecret = null;
			this.responseProt = null;
			this.allowCustomCertSerno = false;
		}
		// Checks if an extended user data hander is configured and if so, creates the handler class.
		final String handlerClass = CmpConfiguration.getCertReqHandlerClass();
		if ( handlerClass!=null ) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("CertReqHandlerClass="+handlerClass);
			}
			ExtendedUserDataHandler tmp;
			try {
				tmp = (ExtendedUserDataHandler)Class.forName(handlerClass).newInstance();
			} catch (Exception e) {
				tmp = null;
				LOG.warn("The configured unid class '"+handlerClass+"' is not existing.");
			}
			this.extendedUserDataHandler = tmp;			
		} else {
			this.extendedUserDataHandler = null;
		}
	}

	public ResponseMessage handleMessage(final BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		ResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq = null;
			if (msg instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) msg;
				crmfreq.getMessage();
				// If we have usernameGeneratorParams we want to generate usernames automagically for requests
				// If we are not in RA mode, usernameGeneratorParams will be null
				if (usernameGenParams != null) {
					resp = handleRaMessage(msg, crmfreq);
				} else {
					// Try to find the user that is the subject for the request
					// if extractUsernameComponent is null, we have to find the user from the DN
					// if not empty the message will find the username itself, in the getUsername method
					final String dn = crmfreq.getSubjectDN();
					final EndEntityInformation data;
					/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
					final String usernameComp = CmpConfiguration.getExtractUsernameComponent();
					if (LOG.isDebugEnabled()) {
						LOG.debug("extractUsernameComponent: "+usernameComp);
					}
					if (StringUtils.isEmpty(usernameComp)) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("looking for user with dn: "+dn);
						}
						data = userAdminSession.findUserBySubjectDN(admin, dn);
					} else {
						final String username = CertTools.getPartFromDN(dn,usernameComp);
						if (LOG.isDebugEnabled()) {
							LOG.debug("looking for user with username: "+username);
						}						
						data = userAdminSession.findUser(admin, username);
					}
					if (data != null) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Found username: "+data.getUsername());
						}
						crmfreq.setUsername(data.getUsername());
					} else {
						final String errMsg = INTRES.getLocalizedMessage("cmp.infonouserfordn", dn);
						LOG.info(errMsg);
					}
				}
			} else {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errornocmrfreq");
				LOG.error(errMsg);
			}
			// This is a request message, so we want to enroll for a certificate, if we have not created an error already
			if (resp == null) {
				// Get the certificate
				resp = signSession.createCertificate(admin, crmfreq, org.ejbca.core.protocol.cmp.CmpResponseMessage.class, null);				
			}
			if (resp == null) {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
				LOG.error(errMsg);
			}
		} catch (AuthorizationDeniedException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e);			
		} catch (IllegalKeyException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.error(errMsg, e);			
		} catch (CADoesntExistsException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it	
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.WRONG_AUTHORITY, e.getMessage());
		} catch (SignRequestException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (SignRequestSignatureException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_POP, e.getMessage());
        } catch (CesecoreException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
        } catch (EjbcaException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
            LOG.info(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (ClassNotFoundException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
			LOG.error(errMsg, e);			
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
	 * @param msg
	 * @param crmfreq
	 * @return IResponseMessage that can be sent back to the client
	 * @throws AuthorizationDeniedException
	 * @throws EjbcaException
	 * @throws ClassNotFoundException
	 * @throws CesecoreException 
	 */
	private ResponseMessage handleRaMessage(final BaseCmpMessage msg, final CrmfRequestMessage crmfreq) throws AuthorizationDeniedException, EjbcaException, ClassNotFoundException, CesecoreException {
		final int eeProfileId;        // The endEntityProfile to be used when adding users in RA mode.
		final int caId;           // The CA to user when adding users in RA mode
		final String certProfileName;  // The certificate profile to use when adding users in RA mode.
		final int certProfileId;
		// Try to find a HMAC/SHA1 protection key
		final int requestId = crmfreq.getRequestId();
		final int requestType = crmfreq.getRequestType();
		ResponseMessage resp = null; // The CMP response message to be sent back to the client
		final String keyId = getSenderKeyId(crmfreq.getHeader());
		if (keyId == null) {			// No keyId found in message so we can not authenticate it.
			final String errMsg = INTRES.getLocalizedMessage("cmp.errorunauthmessagera");
			LOG.info(errMsg); // info because this is something we should expect and we handle it
			return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		}
		try {
			final CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());
			// If we use a globally configured shared secret for all CAs we check it right away
			if (this.raAuthSecret != null && !verifyer.verify(this.raAuthSecret)) {
				String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Global auth secret");
				LOG.info(errMsg); // info because this is something we should expect and we handle it
				if (verifyer.getErrMsg() != null) {
					errMsg = verifyer.getErrMsg();
				}
				return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
			}
			try {
				eeProfileId = getUsedEndEntityProfileId(keyId);
				caId = getUsedCaId(keyId, eeProfileId);
				certProfileName = getUsedCertProfileName(keyId);
				certProfileId = getUsedCertProfileId(certProfileName);
			} catch (CADoesntExistsException e) {
				LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
				if (this.raAuthSecret == null) {
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
				}
				return CmpMessageHelper.createErrorMessage(msg, FailInfo.INCORRECT_DATA, e.getMessage(), requestId, requestType, verifyer, keyId, this.responseProt);
			}
			// Now we know which CA the request is for, if we didn't use a global shared secret we can check it now!
			if (this.raAuthSecret == null) {
				try {
					CAInfo caInfo = this.caSession.getCAInfo(this.admin, caId);
					String cmpRaAuthSecret = null;  
					if (caInfo instanceof X509CAInfo) {
						cmpRaAuthSecret = ((X509CAInfo) caInfo).getCmpRaAuthSecret();
					}
					if (StringUtils.isEmpty(cmpRaAuthSecret) || !verifyer.verify(cmpRaAuthSecret)) {
						String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Auth secret for CAId="+caId);
						if (StringUtils.isEmpty(cmpRaAuthSecret)) {
							errMsg += " Secret is empty";
						} else {
							errMsg += " Secret fails verify";
						}
						LOG.info(errMsg); // info because this is something we should expect and we handle it
						if (verifyer.getErrMsg() != null) {
							errMsg = verifyer.getErrMsg();
						}
						return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
					}					
				} catch (CADoesntExistsException e) {
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
				}
			}
			// Create a username and password and register the new user in EJBCA
			final UsernameGenerator gen = UsernameGenerator.getInstance(this.usernameGenParams);
			// Don't convert this DN to an ordered EJBCA DN string with CertTools.stringToBCDNString because we don't want double escaping of some characters
			final RequestMessage req =  this.extendedUserDataHandler!=null ? this.extendedUserDataHandler.processRequestMessage(crmfreq, certProfileName) : crmfreq;
			final X509Name dnname = req.getRequestX509Name();
			if (LOG.isDebugEnabled()) {
				LOG.debug("Creating username from base dn: "+dnname.toString());
			}
			final String username = gen.generateUsername(dnname.toString());
			final String pwd;
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
			// AltNames may be in the request template
			final String altNames = req.getRequestAltNames();
			final String email;
			final List<String> emails = CertTools.getEmailFromDN(altNames);
			emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
			if (!emails.isEmpty()) {
				email = emails.get(0); // Use rfc822name or first SubjectDN email address as user email address if available
			} else {
				email = null;
			}
			final ExtendedInformation ei;
			if (this.allowCustomCertSerno) {
				// Don't even try to parse out the field if it is not allowed
				BigInteger customCertSerno = crmfreq.getSubjectCertSerialNo();
				if (customCertSerno != null) {
					// If we have a custom certificate serial number in the request, we will pass it on to the UserData object
					ei = new ExtendedInformation();
					ei.setCertificateSerialNumber(customCertSerno);
					if (LOG.isDebugEnabled()) {
						LOG.debug("Custom certificate serial number: "+customCertSerno.toString(16));					
					}
				} else {
					ei = null;
				}
			} else {
				ei = null;
			}
			final EndEntityInformation userdata = new EndEntityInformation(username, dnname.toString(), caId, altNames, email, UserDataConstants.STATUS_NEW, SecConst.USER_ENDUSER, eeProfileId, certProfileId, null, null, SecConst.TOKEN_SOFT_BROWSERGEN, 0, ei);
			userdata.setPassword(pwd);
			// Set so we have the right params in the call to processCertReq. 
			// Username and pwd in the UserDataVO and the IRequestMessage must match
			crmfreq.setUsername(username);
			crmfreq.setPassword(pwd);
			// Set all protection parameters
			final String pbeDigestAlg = verifyer.getOwfOid();
			final String pbeMacAlg = verifyer.getMacOid();
			final int pbeIterationCount = verifyer.getIterationCount();
			final String raSecret = verifyer.getLastUsedRaSecret();
			if (LOG.isDebugEnabled()) {
				LOG.debug("responseProt="+this.responseProt+", pbeDigestAlg="+pbeDigestAlg+", pbeMacAlg="+pbeMacAlg+", keyId="+keyId+", raSecret="+(raSecret == null ? "null":"not null"));
			}
			if (StringUtils.equals(this.responseProt, "pbe")) {
				crmfreq.setPbeParameters(keyId, raSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
			}
			try {
				try {
					if (LOG.isDebugEnabled()) {
						LOG.debug("Creating new request with eeProfileId '"+eeProfileId+"', certProfileId '"+certProfileId+"', caId '"+caId+"'");                                                               
					}
					resp = this.certificateRequestSession.processCertReq(this.admin, userdata, req, org.ejbca.core.protocol.cmp.CmpResponseMessage.class);
				} catch (PersistenceException e) {
					// CreateException will catch also DuplicateKeyException because DuplicateKeyException is a subclass of CreateException 
					// This was very strange, we didn't find it before, but now it exists?
					// This should never happen when using the "single transaction" request session??
					final String updateMsg = INTRES.getLocalizedMessage("cmp.erroradduserupdate", username);
					LOG.info(updateMsg);
					// Try again
					resp = this.certificateRequestSession.processCertReq(this.admin, userdata, req, org.ejbca.core.protocol.cmp.CmpResponseMessage.class);
				}
			} catch (UserDoesntFullfillEndEntityProfile e) {
				LOG.error(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
				resp = CmpMessageHelper.createErrorMessage(msg, FailInfo.INCORRECT_DATA, e.getMessage(), requestId, requestType, verifyer, keyId, this.responseProt);
			} catch (ApprovalException e) {
				LOG.error(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
				resp = CmpMessageHelper.createErrorMessage(msg, FailInfo.NOT_AUTHORIZED, e.getMessage(), requestId, requestType, verifyer, keyId, this.responseProt);
			} catch (PersistenceException e) {
				LOG.error(INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username), e);
				resp = CmpMessageHelper.createErrorMessage(msg, FailInfo.NOT_AUTHORIZED, e.getMessage(), requestId, requestType, verifyer, keyId, this.responseProt);
			}
		} catch (NoSuchAlgorithmException e) {
			LOG.info(INTRES.getLocalizedMessage("cmp.errorcalcprotection"), e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
		} catch (NoSuchProviderException e) {
			LOG.error(INTRES.getLocalizedMessage("cmp.errorcalcprotection"), e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
		} catch (InvalidKeyException e) {
			LOG.info(INTRES.getLocalizedMessage("cmp.errorcalcprotection"), e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
		} catch (HandlerException e) {
			LOG.error(INTRES.getLocalizedMessage("cmp.errorexthandlerexec"), e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
		}
		return resp;
	}
}
