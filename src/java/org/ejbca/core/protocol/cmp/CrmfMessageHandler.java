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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.ICertificateRequestSessionHome;
import org.ejbca.core.ejb.ra.ICertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import com.novosec.pkix.asn1.cmp.PKIHeader;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id$
 */
public class CrmfMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(CrmfMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    /** strings for error messages defined in internal resources */
	private static final String CMP_ERRORADDUSER = "cmp.erroradduser";
	private static final String CMP_ERRORGENERAL = "cmp.errorgeneral";

	/** Parameters used for username generation if we are using RA mode to create users */
	private UsernameGeneratorParams usernameGenParams = null;
	/** Parameters used for temporary password generation */
	private String userPwdParams = "random";
	/** The endEntityProfile to be used when adding users in RA mode */
	private int eeProfileId = 0;
	/** The certificate profile to use when adding users in RA mode */
	private int certProfileId = 0;
	/** The CA to user when adding users in RA mode */
	private int caId = 0;
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProt = null;
	
	private final Admin admin;
	private final ISignSessionRemote signsession;
	private final IUserAdminSessionRemote usersession;
	private final ICAAdminSessionRemote casession;
	private final IRaAdminSessionRemote rasession;
	private final ICertificateStoreSessionRemote storesession;
	private final ICertificateRequestSessionRemote reqsession;
	
	public CrmfMessageHandler(final Admin admin) throws CreateException, RemoteException {
		this.admin = admin;
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		final ISignSessionHome signHome = (ISignSessionHome)ServiceLocator.getInstance().getRemoteHome(ISignSessionHome.JNDI_NAME, ISignSessionHome.class);		
		final IUserAdminSessionHome userHome = (IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class);
		final ICAAdminSessionHome caHome = (ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class);
		final IRaAdminSessionHome raHome = (IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class);
		final ICertificateStoreSessionHome storeHome = (ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class);
		final ICertificateRequestSessionHome reqHome = (ICertificateRequestSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateRequestSessionHome.JNDI_NAME, ICertificateRequestSessionHome.class);

		this.signsession = signHome.create();
		this.usersession = userHome.create();
		this.casession = caHome.create();
		this.rasession = raHome.create();
		this.storesession = storeHome.create();
		this.reqsession = reqHome.create();

		if (CmpConfiguration.getRAOperationMode()) {
			// create UsernameGeneratorParams
			usernameGenParams = new UsernameGeneratorParams();
			usernameGenParams.setMode(CmpConfiguration.getRANameGenerationScheme());
			usernameGenParams.setDNGeneratorComponent(CmpConfiguration.getRANameGenerationParameters());
			usernameGenParams.setPrefix(CmpConfiguration.getRANameGenerationPrefix());
			usernameGenParams.setPostfix(CmpConfiguration.getRANameGenerationPostfix());
			
			userPwdParams =  CmpConfiguration.getUserPasswordParams();
			
			raAuthSecret = CmpConfiguration.getRAAuthenticationSecret();
			final String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
			if (StringUtils.equals(endEntityProfile, "KeyId")) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using End Entity Profile with same name as KeyId in request.");
				}
				eeProfileId = -1;
			} else {
				eeProfileId = rasession.getEndEntityProfileId(admin, endEntityProfile);
			}
			final String certificateProfile = CmpConfiguration.getRACertificateProfile();
			if (StringUtils.equals(certificateProfile, "KeyId")) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using Certificate Profile with same name as KeyId in request.");
				}
				certProfileId = -1;
			} else {
				certProfileId = storesession.getCertificateProfileId(admin, certificateProfile);					
			}
			final String caName = CmpConfiguration.getRACAName();
			if (StringUtils.equals(caName, "ProfileDefault")) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using default CA from End Entity Profile CA when adding users in RA mode.");
				}
				caId = -1;
			} else if (StringUtils.equals(caName, "KeyId")) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using keyId as CA name when adding users in RA mode.");
				}
				caId = -2;										
			} else {
				final CAInfo info = casession.getCAInfo(admin, caName);
				caId = info.getCAId();					
				if (LOG.isDebugEnabled()) {
					LOG.debug("Using fixed caName when adding users in RA mode: "+caName+"("+caId+")");
				}
			}
			responseProt = CmpConfiguration.getResponseProtection();
			if (LOG.isDebugEnabled()) {
				LOG.debug("cmp.operationmode=ra");
				LOG.debug("cmp.responseprotection="+responseProt);
			}

		}
	}

	public IResponseMessage handleMessage(final BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		IResponseMessage resp = null;
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
					final UserDataVO data;
					/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
					final String usernameComp = CmpConfiguration.getExtractUsernameComponent();
					if (LOG.isDebugEnabled()) {
						LOG.debug("extractUsernameComponent: "+usernameComp);
					}
					if (StringUtils.isEmpty(usernameComp)) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("looking for user with dn: "+dn);
						}
						data = usersession.findUserBySubjectDN(admin, dn);
					} else {
						final String username = CertTools.getPartFromDN(dn,usernameComp);
						if (LOG.isDebugEnabled()) {
							LOG.debug("looking for user with username: "+username);
						}						
						data = usersession.findUser(admin, username);
					}
					if (data != null) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Found username: "+data.getUsername());
						}
						crmfreq.setUsername(data.getUsername());
					} else {
						final String errMsg = INTRES.getLocalizedMessage("cmp.infonouserfordn");
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
				resp = signsession.createCertificate(admin, crmfreq, -1,
						Class.forName(org.ejbca.core.protocol.cmp.CmpResponseMessage.class.getName()));				
			}
			if (resp == null) {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errornullresp");
				LOG.error(errMsg);
			}
		} catch (AuthorizationDeniedException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.error(errMsg, e);			
		} catch (IllegalKeyException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.error(errMsg, e);			
		} catch (CADoesntExistsException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it	
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.WRONG_AUTHORITY, e.getMessage());
		} catch (SignRequestException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (SignRequestSignatureException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.info(errMsg, e); // info because this is something we should expect and we handle it
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_POP, e.getMessage());
        } catch (EjbcaException e) {
            final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
            LOG.error(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (ClassNotFoundException e) {
			final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
			LOG.error(errMsg, e);			
		} catch (RemoteException e) {
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
	 * @throws RemoteException
	 * @throws AuthorizationDeniedException
	 * @throws EjbcaException
	 * @throws ClassNotFoundException
	 */
	private IResponseMessage handleRaMessage(final BaseCmpMessage msg, final CrmfRequestMessage crmfreq) throws RemoteException,
			AuthorizationDeniedException, EjbcaException, ClassNotFoundException {
		// Try to find a HMAC/SHA1 protection key
		final int requestId = crmfreq.getRequestId();
		final int requestType = crmfreq.getRequestType();
		final PKIHeader head = crmfreq.getHeader();
		final DEROctetString os = head.getSenderKID();
		IResponseMessage resp = null; // The CMP response message to be sent back to the client
		if (os == null) {
			// No keyId found in message so we can not authenticate it.
			final String errMsg = INTRES.getLocalizedMessage("cmp.errorunauthmessagera");
			LOG.info(errMsg); // info because this is something we should expect and we handle it
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
		} else {
			String keyId;
			try {
				keyId = new String(os.getOctets(), "UTF-8");
			} catch (UnsupportedEncodingException e2) {
				keyId = new String(os.getOctets());
				LOG.info("UTF-8 not available, using platform default encoding for keyId.");
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("Found a sender keyId: "+keyId);
			}
			if (keyId == null) {
				LOG.error("No KeyId contained in CMP request.");
			}
			try {
				final CmpPbeVerifyer verifyer = new CmpPbeVerifyer(raAuthSecret, msg.getMessage());
				final boolean ret = verifyer.verify();
				final String pbeDigestAlg = verifyer.getOwfOid();
				final String pbeMacAlg = verifyer.getMacOid();
				final int pbeIterationCount = verifyer.getIterationCount();
				if (ret) {
					// If authentication was correct, we will now create a username and password and register the new user in EJBCA
					final UsernameGenerator gen = UsernameGenerator.getInstance(usernameGenParams);
					// Don't convert this DN to an ordered EJBCA DN string with CertTools.stringToBCDNString because we don't want double escaping of some characters
					final X509Name dnname = crmfreq.getRequestX509Name();
					if (LOG.isDebugEnabled()) {
						LOG.debug("Creating username from base dn: "+dnname.toString());
					}
					final String username = gen.generateUsername(dnname.toString());
					String pwd;
					if (StringUtils.equals(userPwdParams, "random")) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Setting 12 char random user password.");
						}
						final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
						pwd = pwdgen.getNewPassword(12, 12);									
					} else {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Setting fixed user password from config.");
						}
						pwd = userPwdParams;									
					}
					// AltNames may be in the request template
					final String altNames = crmfreq.getRequestAltNames();
					boolean addedUser = false; // flag indicating if adding was successful
					String failText = null;
					FailInfo failInfo = null;
					try {
						if (eeProfileId == -1) {
							if (LOG.isDebugEnabled()) {
								LOG.debug("Using end entity profile with name: "+keyId);
							}
							eeProfileId = rasession.getEndEntityProfileId(admin, keyId);
							if (eeProfileId == 0) {
								LOG.info("No end entity profile found matching keyId: "+keyId);
								throw new NotFoundException("End entity profile with name '"+keyId+"' not found.");
							}
						}
						if (certProfileId == -1) {
							if (LOG.isDebugEnabled()) {
								LOG.debug("Using certificate profile with name: "+keyId);
							}
							certProfileId = storesession.getCertificateProfileId(admin, keyId);
							if (certProfileId == 0) {
								LOG.info("No certificate profile found matching keyId: "+keyId);
								throw new NotFoundException("Certificate profile with name '"+keyId+"' not found.");
							}
						}
						if (caId == -1) {
							// get default CA id from end entity profile
							final EndEntityProfile eeProfile = rasession.getEndEntityProfile(admin, eeProfileId);
							caId = eeProfile.getDefaultCA();
							if (caId == -1) {
								LOG.error("No default CA id for end entity profile: "+eeProfileId);
							} else {
								if (LOG.isDebugEnabled()) {
									LOG.debug("Using CA with id: "+caId);
								}
							}
						} else if (caId == -2) {
							// Use keyId as CA name
							final CAInfo info = casession.getCAInfo(admin, keyId);
							if (info == null) {
								LOG.info("No CA found matching keyId: "+keyId);
								throw new NotFoundException("CA with name '"+keyId+"' not found");
							}
							if (LOG.isDebugEnabled()) {
								LOG.debug("Using CA: "+info.getName());
							}
							caId = info.getCAId();																	
						}
						
						String email = null;
						final List emails = CertTools.getEmailFromDN(altNames);
						emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
						if (!emails.isEmpty()) {
							email = (String) emails.get(0);	// Use rfc822name or first SubjectDN email address as user email address if available
						}
						// Set all protection parameters
						if (LOG.isDebugEnabled()) {
							LOG.debug(responseProt+", "+pbeDigestAlg+", "+pbeMacAlg+", "+keyId+", "+raAuthSecret);
						}
						if (StringUtils.equals(responseProt, "pbe")) {
							crmfreq.setPbeParameters(keyId, raAuthSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
						}
						// Now we are all set to go ahead and generate a certificate for the poor bastard
						crmfreq.setUsername(username); // so we have the right params in the call to processCertReq
						crmfreq.setPassword(pwd);
						final UserDataVO userdata = new UserDataVO(username, dnname.toString(), caId, altNames, email, UserDataConstants.STATUS_NEW, SecConst.USER_ENDUSER, eeProfileId, certProfileId, null, null, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
						userdata.setPassword(pwd);
						try {
							if (LOG.isDebugEnabled()) {
								LOG.debug("Creating new user with eeProfileId '"+eeProfileId+"', certProfileId '"+certProfileId+"', caId '"+caId+"'");												
							}
							resp = reqsession.processCertReq(admin, userdata, crmfreq, Class.forName(org.ejbca.core.protocol.cmp.CmpResponseMessage.class.getName()));
							addedUser = true;
						} catch (CreateException e) {
							// CreateException will catch also DuplicateKeyException because DuplicateKeyException is a subclass of CreateException 
							// This was very strange, we didn't find it before, but now it exists?
							// This should never happen when using the "single transaction" request session??
							final String updateMsg = INTRES.getLocalizedMessage("cmp.erroradduserupdate", username);
							LOG.info(updateMsg);
							// Try again
							resp = reqsession.processCertReq(admin, userdata, crmfreq, Class.forName(org.ejbca.core.protocol.cmp.CmpResponseMessage.class.getName()));
							addedUser = true;
						}
					} catch (NotFoundException e) {
						final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage());
						LOG.info(errMsg, e);
						failText = e.getMessage();
						failInfo = FailInfo.INCORRECT_DATA;
					} catch (UserDoesntFullfillEndEntityProfile e) {
						final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username);
						LOG.error(errMsg, e);
						failText = e.getMessage();
						failInfo = FailInfo.INCORRECT_DATA;
					} catch (ApprovalException e) {
						final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username);
						LOG.error(errMsg, e);
						failText = e.getMessage();
						failInfo = FailInfo.NOT_AUTHORIZED;
					} catch (DuplicateKeyException e) {
						final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER, username);
						LOG.error(errMsg, e);
						failText = e.getMessage();
						failInfo = FailInfo.NOT_AUTHORIZED;
					}
					if (!addedUser) {
						final CmpErrorResponseMessage cresp = new CmpErrorResponseMessage();
						cresp.setRecipientNonce(msg.getSenderNonce());
						cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
						cresp.setSender(msg.getRecipient());
						cresp.setRecipient(msg.getSender());
						cresp.setTransactionId(msg.getTransactionId());
						cresp.setFailText(failText);
						cresp.setFailInfo(failInfo);
						cresp.setRequestId(requestId);
						cresp.setRequestType(requestType);
						
						// Set all protection parameters, this is another message than if we generated a cert above
						if (StringUtils.equals(responseProt, "pbe") && (pbeDigestAlg != null) && (pbeMacAlg != null) && (keyId != null) && (raAuthSecret != null) ) {
							cresp.setPbeParameters(keyId, raAuthSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
						}
						resp = cresp;
						try {
							// Here we need to create the response message, when coming from SignSession it has already been "created"
							resp.create();
						} catch (InvalidKeyException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						} catch (NoSuchAlgorithmException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						} catch (NoSuchProviderException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						} catch (SignRequestException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						} catch (NotFoundException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						} catch (IOException e1) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORGENERAL);
							LOG.error(errMsg, e1);
						}																
					}
				} else {
					String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage");
					LOG.info(errMsg); // info because this is something we should expect and we handle it
					if (verifyer.getErrMsg() != null) {
						errMsg = verifyer.getErrMsg();
					}
					resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);					        	
				}
			} catch (NoSuchAlgorithmException e) {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.info(errMsg, e);
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			} catch (NoSuchProviderException e) {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.error(errMsg, e);
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			} catch (InvalidKeyException e) {
				final String errMsg = INTRES.getLocalizedMessage("cmp.errorcalcprotection");
				LOG.info(errMsg, e);
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
			}
		} // if (os == null) .. else ...
		return resp;
	}
	
}
