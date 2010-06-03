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
import javax.ejb.FinderException;

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
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
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
	
	private static Logger log = Logger.getLogger(CrmfMessageHandler.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = null;
	/** Parameters used for username generation if we are using RA mode to create users */
	private UsernameGeneratorParams usernameGeneratorParams = null;
	/** Parameters used for temporary password generation */
	private String userPasswordParams = "random";
	/** The endEntityProfile to be used when adding users in RA mode */
	private int eeProfileId = 0;
	/** The certificate profile to use when adding users in RA mode */
	private int certProfileId = 0;
	/** The CA to user when adding users in RA mode */
	private int caId = 0;
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	
	private Admin admin;
	private ISignSessionRemote signsession = null;
	private IUserAdminSessionRemote usersession = null;
	private ICAAdminSessionRemote casession = null;
	private IRaAdminSessionRemote rasession = null;
	private ICertificateStoreSessionRemote storesession = null;
	
	public CrmfMessageHandler(Admin admin) throws CreateException, RemoteException {
		this.admin = admin;
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		ISignSessionHome signHome = (ISignSessionHome)ServiceLocator.getInstance().getRemoteHome(ISignSessionHome.JNDI_NAME, ISignSessionHome.class);		
		IUserAdminSessionHome userHome = (IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class);
		ICAAdminSessionHome caHome = (ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class);
		IRaAdminSessionHome raHome = (IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class);
		ICertificateStoreSessionHome storeHome = (ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class);
		this.signsession = signHome.create();
		this.usersession = userHome.create();
		this.casession = caHome.create();
		this.rasession = raHome.create();
		this.storesession = storeHome.create();

		if (CmpConfiguration.getRAOperationMode()) {
			// create UsernameGeneratorParams
			usernameGeneratorParams = new UsernameGeneratorParams();
			usernameGeneratorParams.setMode(CmpConfiguration.getRANameGenerationScheme());
			usernameGeneratorParams.setDNGeneratorComponent(CmpConfiguration.getRANameGenerationParameters());
			usernameGeneratorParams.setPrefix(CmpConfiguration.getRANameGenerationPrefix());
			usernameGeneratorParams.setPostfix(CmpConfiguration.getRANameGenerationPostfix());
			
			userPasswordParams =  CmpConfiguration.getUserPasswordParams();
			
			raAuthenticationSecret = CmpConfiguration.getRAAuthenticationSecret();
			String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
			if (StringUtils.equals(endEntityProfile, "KeyId")) {
				log.info("Using End Entity Profile with same name as KeyId in request.");
				eeProfileId = -1;
			} else {
				eeProfileId = rasession.getEndEntityProfileId(admin, endEntityProfile);
			}
			String certificateProfile = CmpConfiguration.getRACertificateProfile();
			if (StringUtils.equals(certificateProfile, "KeyId")) {
				log.info("Using Certificate Profile with same name as KeyId in request.");
				certProfileId = -1;
			} else {
				certProfileId = storesession.getCertificateProfileId(admin, certificateProfile);					
			}
			String caName = CmpConfiguration.getRACAName();
			if (StringUtils.equals(caName, "ProfileDefault")) {
				log.info("Using default CA from End Entity Profile CA when adding users in RA mode.");
				caId = -1;
			} else if (StringUtils.equals(caName, "KeyId")) {
				log.info("Using keyId as CA name when adding users in RA mode.");
				caId = -2;										
			} else {
				CAInfo info = casession.getCAInfo(admin, caName);
				caId = info.getCAId();					
			}
			responseProtection = CmpConfiguration.getResponseProtection();
		}
	}

	public IResponseMessage handleMessage(BaseCmpMessage msg) throws NumberFormatException {
		log.trace(">handleMessage");
		IResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq = null;
			if (msg instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) msg;
				crmfreq.getMessage();
				int requestId = crmfreq.getRequestId();
				int requestType = crmfreq.getRequestType();
				// If we have usernameGeneratorParams we want to generate usernames automagically for requests
				// If we are not in RA mode, usernameGeneratorParams will be null
				if (usernameGeneratorParams != null) {
					// Try to find a HMAC/SHA1 protection key
					PKIHeader head = crmfreq.getHeader();
					DEROctetString os = head.getSenderKID();
					if (os != null) {
						String keyId;
						try {
							keyId = new String(os.getOctets(), "UTF-8");
						} catch (UnsupportedEncodingException e2) {
							keyId = new String(os.getOctets());
							log.info("UTF-8 not available, using platform default encoding for keyId.");
						}
						log.debug("Found a sender keyId: "+keyId);
						if (keyId == null) {
							log.error("No KeyId contained in CMP request.");
						}
						try {
							CmpPbeVerifyer verifyer = new CmpPbeVerifyer(raAuthenticationSecret, msg.getMessage());
							boolean ret = verifyer.verify();
							String pbeDigestAlg = verifyer.getOwfOid();
							String pbeMacAlg = verifyer.getMacOid();
							int pbeIterationCount = verifyer.getIterationCount();
							if (ret) {
								// If authentication was correct, we will now create a username and password and register the new user in EJBCA
								UsernameGenerator gen = UsernameGenerator.getInstance(usernameGeneratorParams);
								// Don't convert this DN to an ordered EJBCA DN string with CertTools.stringToBCDNString because we don't want double escaping of some characters
								X509Name dnname = crmfreq.getRequestX509Name();
								log.debug("Creating username from base dn: "+dnname.toString());
								String username = gen.generateUsername(dnname.toString());
								String pwd;
								if (StringUtils.equals(userPasswordParams, "random")) {
									log.debug("Setting 12 char random user password.");
									IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
									pwd = pwdgen.getNewPassword(12, 12);									
								} else {
									log.debug("Setting fixed user password from config.");
									pwd = userPasswordParams;									
								}
								// AltNames may be in the request template
								String altNames = crmfreq.getRequestAltNames();
								boolean addedUser = false; // flag indicating if adding was successful
								String failText = null;
								FailInfo failInfo = null;
								try {
									if (eeProfileId == -1) {
										log.debug("Using end entity profile with name: "+keyId);
										eeProfileId = rasession.getEndEntityProfileId(admin, keyId);
										if (eeProfileId == 0) {
											log.info("No end entity profile found matching keyId: "+keyId);
											throw new NotFoundException("End entity profile with name '"+keyId+"' not found");
										}
									}
									if (certProfileId == -1) {
										log.debug("Using certificate profile with name: "+keyId);
										certProfileId = storesession.getCertificateProfileId(admin, keyId);
										if (certProfileId == 0) {
											log.info("No certificate profile found matching keyId: "+keyId);
											throw new NotFoundException("Certificate profile with name '"+keyId+"' not found");
										}
									}
									if (caId == -1) {
										// get default CA id from end entity profile
										EndEntityProfile eeProfile = rasession.getEndEntityProfile(admin, eeProfileId);
										String name = rasession.getEndEntityProfileName(admin, eeProfileId);
										caId = eeProfile.getDefaultCA();
										if (caId == -1) {
											log.error("No default CA id for end entity profile: "+name);
										} else {
											CAInfo info = casession.getCAInfo(admin, caId);													
											log.debug("Using CA: "+info.getName());
										}
									} else if (caId == -2) {
										// Use keyId as CA name
										CAInfo info = casession.getCAInfo(admin, keyId);
										if (info == null) {
											log.info("No CA found matching keyId: "+keyId);
											throw new NotFoundException("CA with name '"+keyId+"' not found");
										}
										log.debug("Using CA: "+info.getName());
										caId = info.getCAId();																	
									}
									
									// See if the user already exists so we should change it or create it
									UserDataVO user = null;
									try {
										user = usersession.findUser(admin, username);
									} catch (FinderException e) {
										// User can not be found, leave user as null
									}
									String email = null;
									List emails = CertTools.getEmailFromDN(altNames);
									emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
									if (!emails.isEmpty()) {
										email = (String) emails.get(0);	// Use rfc822name or first SubjectDN email address as user email address if available
									}
									if (user == null) {
										try {
											if (log.isDebugEnabled()) {
												log.debug("Creating new user with eeProfileId '"+eeProfileId+"', certProfileId '"+certProfileId+"', caId '"+caId+"'");												
											}
											usersession.addUser(admin, username, pwd, dnname.toString(), altNames, email, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, caId);												
										} catch (CreateException e) {
											// CreateException will catch also DuplicateKeyException because DuplicateKeyException is a subclass of CreateException 
											// This was very strange, we didn't find it before, but now it exists?
											// This will happen if we get virtually parallel requests for the same user
											String updateMsg = intres.getLocalizedMessage("cmp.erroradduserupdate", username);
											log.info(updateMsg);
											// If the user already exists, we will change him instead and go for that
											usersession.changeUser(admin, username, pwd, dnname.toString(), altNames, email, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, UserDataConstants.STATUS_NEW, caId);										
										} catch (FinderException e){
											e.printStackTrace();
										}
									} else {
										// If the user already exists, we will change him instead and go for that
										log.debug("User already exists, so we will update instead.");
										if (log.isDebugEnabled()) {
											log.debug("Changing user to eeProfileId '"+eeProfileId+"', certProfileId '"+certProfileId+"', caId '"+caId+"'");												
										}
										usersession.changeUser(admin, username, pwd, dnname.toString(), altNames, email, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, UserDataConstants.STATUS_NEW, caId);										
									}
									addedUser = true;
								} catch (NotFoundException e) {
									String errMsg = intres.getLocalizedMessage("cmp.errorgeneral", e.getMessage());
									log.info(errMsg, e);
									failText = e.getMessage();
								} catch (UserDoesntFullfillEndEntityProfile e) {
									String errMsg = intres.getLocalizedMessage("cmp.erroradduser", username);
									log.error(errMsg, e);
									failText = e.getMessage();
								} catch (ApprovalException e) {
									String errMsg = intres.getLocalizedMessage("cmp.erroradduser", username);
									log.error(errMsg, e);
									failText = e.getMessage();
									failInfo = FailInfo.NOT_AUTHORIZED;
								} catch (WaitingForApprovalException e) {
									String errMsg = intres.getLocalizedMessage("cmp.erroradduser", username);
									log.error(errMsg, e);
									failText = e.getMessage();
									failInfo = FailInfo.NOT_AUTHORIZED;
								}
								if (!addedUser) {
									CmpErrorResponseMessage cresp = new CmpErrorResponseMessage();
									cresp.setRecipientNonce(msg.getSenderNonce());
									cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
									cresp.setSender(msg.getRecipient());
									cresp.setRecipient(msg.getSender());
									cresp.setTransactionId(msg.getTransactionId());
									cresp.setFailText(failText);
									cresp.setFailInfo(failInfo);
									cresp.setRequestId(requestId);
									cresp.setRequestType(requestType);
									
									// Set all protection parameters
									log.debug(responseProtection+", "+pbeDigestAlg+", "+pbeMacAlg+", "+keyId+", "+raAuthenticationSecret);
									if (StringUtils.equals(responseProtection, "pbe") && (pbeDigestAlg != null) && (pbeMacAlg != null) && (keyId != null) && (raAuthenticationSecret != null) ) {
										cresp.setPbeParameters(keyId, raAuthenticationSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
									}
									resp = cresp;
									try {
										resp.create();
									} catch (InvalidKeyException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									} catch (NoSuchAlgorithmException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									} catch (NoSuchProviderException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									} catch (SignRequestException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									} catch (NotFoundException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									} catch (IOException e1) {
										String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
										log.error(errMsg, e1);
									}																
								}
								crmfreq.setUsername(username);
								crmfreq.setPassword(pwd);
								// Set all protection parameters
								if (StringUtils.equals(responseProtection, "pbe")) {
									crmfreq.setPbeParameters(keyId, raAuthenticationSecret, pbeDigestAlg, pbeMacAlg, pbeIterationCount);
								}
								// Now we are all set to go ahead and generate a certificate for the poor bastard
							} else {
								String errMsg = intres.getLocalizedMessage("cmp.errorauthmessage");
								log.error(errMsg);
								if (verifyer.getErrMsg() != null) {
									errMsg = verifyer.getErrMsg();
								}
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);					        	
							}
						} catch (NoSuchAlgorithmException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.info(errMsg, e);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
						} catch (NoSuchProviderException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.error(errMsg, e);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
						} catch (InvalidKeyException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.info(errMsg, e);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
						}
					} else {
						String errMsg = intres.getLocalizedMessage("cmp.errorunauthmessagera");
						log.error(errMsg);
						resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
					}
				} else {
					// Try to find the user that is the subject for the request
					// if extractUsernameComponent is null, we have to find the user from the DN
					// if not empty the message will find the username itself, in the getUsername method
					if (StringUtils.isEmpty(extractUsernameComponent)) {
						String dn = crmfreq.getSubjectDN();
						log.debug("looking for user with dn: "+dn);
						UserDataVO data = usersession.findUserBySubjectDN(admin, dn);
						if (data != null) {
							log.debug("Found username: "+data.getUsername());
							crmfreq.setUsername(data.getUsername());
						} else {
							String errMsg = intres.getLocalizedMessage("cmp.infonouserfordn");
							log.info(errMsg);
						}
					}
				}
			} else {
				String errMsg = intres.getLocalizedMessage("cmp.errornocmrfreq");
				log.error(errMsg);
			}
			// This is a request message, so we want to enroll for a certificate, if we have not created an error already
			if (resp == null) {
				// Get the certificate
				resp = signsession.createCertificate(admin, crmfreq, -1,
						Class.forName(org.ejbca.core.protocol.cmp.CmpResponseMessage.class.getName()));				
			}
			if (resp == null) {
				String errMsg = intres.getLocalizedMessage("cmp.errornullresp");
				log.error(errMsg);
			}
		} catch (AuthorizationDeniedException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
		} catch (IllegalKeyException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
		} catch (CADoesntExistsException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.WRONG_AUTHORITY, e.getMessage());
		} catch (SignRequestException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
		} catch (SignRequestSignatureException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_POP, e.getMessage());
        } catch (EjbcaException e) {
            String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
            log.error(errMsg, e);           
            resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (ClassNotFoundException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
		} catch (RemoteException e) {
			// Fatal error
			String errMsg = intres.getLocalizedMessage("cmp.erroradduser");
			log.error(errMsg, e);			
			resp = null;
		}							
		return resp;
	}
	
}
