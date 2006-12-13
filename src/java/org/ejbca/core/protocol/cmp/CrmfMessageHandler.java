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
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
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
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
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
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import com.novosec.pkix.asn1.cmp.PKIHeader;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: CrmfMessageHandler.java,v 1.18 2006-12-13 09:49:05 anatom Exp $
 */
public class CrmfMessageHandler implements ICmpMessageHandler {
	
	private static Logger log = Logger.getLogger(CrmfMessageHandler.class);
    /** Internal localization of logs and errors */
    private InternalResources intres = InternalResources.getInstance();
	
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = null;
	/** Parameters used for username generation if we are using RA mode to create users */
	private UsernameGeneratorParams usernameGeneratorParams = null;
	/** The endEntityProfile to be used when adding users in RA mode */
	private int eeProfileId = 0;
	/** The certificate profile to use when adding users in RA mode */
	private int certProfileId = 0;
	/** Tha CA to user when adding users in RA mode */
	private int caId = 0;
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of prtection for the response message */
	private String responseProtection = null;
	
	private Admin admin;
	private ISignSessionRemote signsession = null;
	private IUserAdminSessionRemote usersession = null;
	private ICAAdminSessionRemote casession = null;
	private IRaAdminSessionRemote rasession = null;
	private ICertificateStoreSessionRemote storesession = null;
//	private ISignSessionLocal signsession = null;
//	private IUserAdminSessionLocal usersession = null;
//	private ICAAdminSessionLocal casession = null;
//	private IRaAdminSessionLocal rasession = null;
//	private ICertificateStoreSessionLocal storesession = null;
	
	
	public CrmfMessageHandler(Admin admin, Properties prop) throws CreateException, RemoteException {
		this.admin = admin;
		// Get EJB beans, we can not use local beans here because the MBean used for the TCP listener does not work with that
		ISignSessionHome signHome = (ISignSessionHome)ServiceLocator.getInstance().getRemoteHome(ISignSessionHome.JNDI_NAME, ISignSessionHome.class);		
		IUserAdminSessionHome userHome = (IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class);
		ICAAdminSessionHome caHome = (ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class);
		IRaAdminSessionHome raHome = (IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class);
		ICertificateStoreSessionHome storeHome = (ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class);
//		ISignSessionLocalHome signHome = (ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
//		IUserAdminSessionLocalHome userHome = (IUserAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
//		ICAAdminSessionLocalHome caHome = (ICAAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
//		IRaAdminSessionLocalHome raHome = (IRaAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
//		ICertificateStoreSessionLocalHome storeHome = (ICertificateStoreSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
		this.signsession = signHome.create();
		this.usersession = userHome.create();
		this.casession = caHome.create();
		this.rasession = raHome.create();
		this.storesession = storeHome.create();

		String str = prop.getProperty("operationMode");
		log.debug("operationMode="+str);
		if (StringUtils.equalsIgnoreCase(str, "ra")) {
			// create UsernameGeneratorParams
			usernameGeneratorParams = new UsernameGeneratorParams();
			str = prop.getProperty("raModeNameGenerationScheme");
			log.debug("raModeNameGenerationScheme="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setMode(str);
			}
			str = prop.getProperty("raModeNameGenerationParameters");
			log.debug("raModeNameGenerationParameters="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setDNGeneratorComponent(str);
			}
			str = prop.getProperty("raModeNameGenerationPrefix");
			log.debug("raModeNameGenerationPrefix="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setPrefix(str);
			}
			str = prop.getProperty("raModeNameGenerationPostfix");
			log.debug("raModeNameGenerationPostfix="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setPostfix(str);
			}
			str = prop.getProperty("raAuthenticationSecret");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("raAuthenticationSecret is not null");
				raAuthenticationSecret = str;
			}			
			str = prop.getProperty("endEntityProfile");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("endEntityProfile="+str);
				eeProfileId = rasession.getEndEntityProfileId(admin, str);
			}			
			str = prop.getProperty("certificateProfile");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("certificateProfile="+str);
				certProfileId = storesession.getCertificateProfileId(admin, str);
			}			
			str = prop.getProperty("caName");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("caName="+str);
				CAInfo info = casession.getCAInfo(admin, str);
				caId = info.getCAId();
			}			
		}
		str = prop.getProperty("responseProtection");
		if (StringUtils.isNotEmpty(str)) {
			log.debug("responseProtection="+str);
			responseProtection = str;
		}			
	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		log.debug(">handleMessage");
		IResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq = null;
			if (msg instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) msg;
				crmfreq.getMessage();
				int requestId = crmfreq.getRequestId();
				int requestType = crmfreq.getRequestType();
				// If we have usernameGeneratorParams we want to generate usernames automagically for requests
				if (usernameGeneratorParams != null) {
					// Try to find a HMAC/SHA1 protection key
					PKIHeader head = crmfreq.getHeader();
					DEROctetString os = head.getSenderKID();
					if (os != null) {
						String keyId = new String(os.getOctets());
						log.debug("Found a sender keyId: "+keyId);
						try {
							CmpPbeVerifyer verifyer = new CmpPbeVerifyer(raAuthenticationSecret, msg.getMessage());
							boolean ret = verifyer.verify();
							String pbeDigestAlg = verifyer.getOwfOid();
							String pbeMacAlg = verifyer.getMacOid();
							int pbeIterationCount = verifyer.getIterationCount();
							if (ret) {
								// If authentication was correct, we will now create a username and password and register the new user in EJBCA
								UsernameGenerator gen = UsernameGenerator.getInstance(usernameGeneratorParams);
								String dn = crmfreq.getSubjectDN();
								log.debug("Creating username from base dn: "+dn);
								String username = gen.generateUsername(dn);
								IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
								String pwd = pwdgen.getNewPassword(12, 12);
								// AltNames may be in the request template
								String altNames = crmfreq.getRequestAltNames();
								boolean addedUser = false; // flag indicating if adding was succesful
								String failText = null;
								FailInfo failInfo = null;
								try {
									UserDataVO user = null;
									try {
										user = usersession.findUser(admin, username);
									} catch (FinderException e) {
										// User can not be found, leave user as null
									}
									if (user == null) {
										try {
											log.debug("Creating new user.");
											usersession.addUser(admin, username, pwd, dn, altNames, null, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, caId);																					
										} catch (DuplicateKeyException e) {
											// This was veery strange, we didn't find it before, but now it exists?
											String errMsg = intres.getLocalizedMessage("cmp.erroradduserupdate", username);
											log.error(errMsg);
											// If the user already exists, we will change him instead and go for that
											usersession.changeUser(admin, username, pwd, dn, altNames, null, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, UserDataConstants.STATUS_NEW, caId);										
										}
									} else {
										// If the user already exists, we will change him instead and go for that
										log.debug("User already exists, so we will update instead.");
										usersession.changeUser(admin, username, pwd, dn, altNames, null, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, UserDataConstants.STATUS_NEW, caId);										
									}
									addedUser = true;
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
								log.error(msg);
								if (verifyer.getErrMsg() != null) {
									errMsg = verifyer.getErrMsg();
								}
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);					        	
							}
						} catch (NoSuchAlgorithmException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.error(errMsg, e);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
						} catch (NoSuchProviderException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.error(errMsg, e);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
						} catch (InvalidKeyException e) {
							String errMsg = intres.getLocalizedMessage("cmp.errorcalcprotection");
							log.error(errMsg, e);
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
						Class.forName("org.ejbca.core.protocol.cmp.CmpResponseMessage"));				
			}
			if (resp == null) {
				String errMsg = intres.getLocalizedMessage("cmp.errornullresp");
				log.error(errMsg);
			}
		} catch (AuthorizationDeniedException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
		} catch (NotFoundException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (AuthStatusException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (AuthLoginException e) {
			String errMsg = intres.getLocalizedMessage("cmp.errorgeneral");
			log.error(errMsg, e);			
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
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
