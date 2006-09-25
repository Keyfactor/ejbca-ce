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

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
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
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.crmf.PBMParameter;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: CrmfMessageHandler.java,v 1.6 2006-09-25 12:54:59 anatom Exp $
 */
public class CrmfMessageHandler implements ICmpMessageHandler {
	
	private static Logger log = Logger.getLogger(CrmfMessageHandler.class);
	
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
	
	private Admin admin;
	private ISignSessionLocal signsession = null;
	private IUserAdminSessionLocal usersession = null;
	private ICAAdminSessionLocal casession = null;
	private IRaAdminSessionLocal rasession = null;
	private ICertificateStoreSessionLocal storesession = null;
	
	public CrmfMessageHandler(Admin admin) throws CreateException {
		this.admin = admin;
		// Get EJB local bean
		ISignSessionLocalHome signHome = (ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
		this.signsession = signHome.create();
		IUserAdminSessionLocalHome userHome = (IUserAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
		this.usersession = userHome.create();
		ICAAdminSessionLocalHome caHome = (ICAAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
		this.casession = caHome.create();
		IRaAdminSessionLocalHome raHome = (IRaAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
		this.rasession = raHome.create();
		ICertificateStoreSessionLocalHome storeHome = (ICertificateStoreSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
		this.storesession = storeHome.create();
		
		String str = ServiceLocator.getInstance().getString("java:comp/env/operationMode");
		log.debug("operationMode="+str);
		if (StringUtils.equals(str, "RA")) {
			// create UsernameGeneratorParams
			usernameGeneratorParams = new UsernameGeneratorParams();
			str = ServiceLocator.getInstance().getString("java:comp/env/raModeNameGenerationScheme");
			log.debug("raModeNameGenerationScheme="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setMode(str);
			}
			str = ServiceLocator.getInstance().getString("java:comp/env/raModeNameGenerationParameters");
			log.debug("raModeNameGenerationParameters="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setDNGeneratorComponent(str);
			}
			str = ServiceLocator.getInstance().getString("java:comp/env/raModeNameGenerationPrefix");
			log.debug("raModeNameGenerationPrefix="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setPrefix(str);
			}
			str = ServiceLocator.getInstance().getString("java:comp/env/raModeNameGenerationPostfix");
			log.debug("raModeNameGenerationPostfix="+str);
			if (StringUtils.isNotEmpty(str)) {
				usernameGeneratorParams.setPostfix(str);
			}
			str = ServiceLocator.getInstance().getString("java:comp/env/raAuthenticationSecret");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("raAuthenticationSecret is not null");
				raAuthenticationSecret = str;
			}			
			str = ServiceLocator.getInstance().getString("java:comp/env/endEntityProfile");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("endEntityProfile="+str);
				eeProfileId = rasession.getEndEntityProfileId(admin, str);
			}			
			str = ServiceLocator.getInstance().getString("java:comp/env/certificateProfile");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("certificateProfile="+str);
				certProfileId = storesession.getCertificateProfileId(admin, str);
			}			
			str = ServiceLocator.getInstance().getString("java:comp/env/caName");
			if (StringUtils.isNotEmpty(str)) {
				log.debug("caName="+str);
				CAInfo info = casession.getCAInfo(admin, str);
				caId = info.getCAId();
			}			
		}

	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		log.debug(">handleMessage");
		IResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq = null;
			if (msg instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) msg;
				
				// If we have usernameGeneratorParams we want to generate usernames automagically for requests
				if (usernameGeneratorParams != null) {
					// Try to find a HMAC/SHA1 protection key
					PKIHeader head = crmfreq.getHeader();
					DEROctetString os = head.getSenderKID();
					if (os != null) {
						String keyId = new String(os.getOctets());
						log.debug("Found a sender keyId: "+keyId);
						// Verify the PasswordBased protection of the message
						byte[] protectedBytes = crmfreq.getMessage().getProtectedBytes();
						DERBitString protection = crmfreq.getMessage().getProtection();
						AlgorithmIdentifier pAlg = head.getProtectionAlg();
						log.debug("Protection type is: "+pAlg.getObjectId().getId());
						if (!pAlg.getObjectId().equals(CMPObjectIdentifiers.passwordBasedMac)) {
							String errMsg = "Received CMP message with unknown protection alg: "+pAlg.getObjectId().getId();
							log.error(errMsg);
							resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
						} else {
							PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
							int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
							log.debug("Iteration count is: "+iterationCount);
							AlgorithmIdentifier owfAlg = pp.getOwf();
							// Normal OWF alg is 1.3.14.3.2.26 - SHA1
							log.debug("Owf type is: "+owfAlg.getObjectId().getId());
							AlgorithmIdentifier macAlg = pp.getMac();
							// Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
							log.debug("Mac type is: "+macAlg.getObjectId().getId());
							byte[] salt = pp.getSalt().getOctets();
							//log.info("Salt is: "+new String(salt));
							byte[] raSecret = raAuthenticationSecret.getBytes();
							byte[] basekey = new byte[raSecret.length + salt.length];
							for (int i = 0; i < raSecret.length; i++) {
								basekey[i] = raSecret[i];
							}
							for (int i = 0; i < salt.length; i++) {
								basekey[raSecret.length+i] = salt[i];
							}
							try {
								// Construct the base key according to rfc4210, section 5.1.3.1
								MessageDigest dig = MessageDigest.getInstance(owfAlg.getObjectId().getId(), "BC");
								for (int i = 0; i < iterationCount; i++) {
									basekey = dig.digest(basekey);
									dig.reset();
								}
								// For HMAC/SHA1 there is another oid, that is not known in BC, but the result is the same so...
								String macOid = macAlg.getObjectId().getId();
								if (StringUtils.equals("1.3.6.1.5.5.8.1.2", macOid)) {
									macOid = "1.2.840.113549.2.7";
								}
						        Mac mac = Mac.getInstance(macOid, "BC");
						        SecretKey key = new SecretKeySpec(basekey, macOid);
						        mac.init(key);
						        mac.reset();
						        mac.update(protectedBytes, 0, protectedBytes.length);
						        byte[] out = mac.doFinal();
						        // My out should now be the same as the protection bits
						        byte[] pb = protection.getBytes();
						        boolean ret = Arrays.equals(out, pb);
						        if (ret) {
							        // If authentication was correct, we will now create a username and password and register the new user in EJBCA
						        	UsernameGenerator gen = UsernameGenerator.getInstance(usernameGeneratorParams);
									String dn = crmfreq.getSubjectDN();
									log.debug("Creating username from base dn: "+dn);
						        	String username = gen.generateUsername(dn);
						    		IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
						    		String pwd = pwdgen.getNewPassword(12, 12);
						    		usersession.addUser(admin, username, pwd, dn, null, null, false, eeProfileId, certProfileId, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, caId);
						    		crmfreq.setUsername(username);
						    		crmfreq.setPassword(pwd);
						        	// Now we are all set to go ahead and generate a certificate for the poor bastard
						        } else {
									log.error("Authentication failed for message!");
									resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, "Authentication failed for message!");					        	
						        }
							} catch (NoSuchAlgorithmException e) {
								log.error("Exception calculating protection: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
							} catch (NoSuchProviderException e) {
								log.error("Exception calculating protection: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
							} catch (InvalidKeyException e) {
								log.error("Exception calculating protection: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
							} catch (DuplicateKeyException e) {
								log.error("Exception adding user: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
							} catch (UserDoesntFullfillEndEntityProfile e) {
								log.error("Exception adding user: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
							} catch (ApprovalException e) {
								log.error("Exception adding user: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
							} catch (WaitingForApprovalException e) {
								log.error("Exception adding user: ", e);
								resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
							}							
						}
					} else {
						log.error("Recevied an unathenticated message in RA mode!");
						resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, "Recevied an unathenticated message in RA mode!");
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
							log.info("Did not find a username matching dn: "+dn);
						}
					}
				}
			} else {
				log.error("ICmpMessage if not a CrmfRequestMessage!");
			}
			// This is a request message, so we want to enroll for a certificate, if we have not created an error already
			if (resp == null) {
				// Get the certificate
				resp = signsession.createCertificate(admin, crmfreq, -1,
						Class.forName("org.ejbca.core.protocol.cmp.CmpResponseMessage"));				
			}
			if (resp == null) {
				log.error("Response from signSession is null!");
			}
		} catch (AuthorizationDeniedException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (NotFoundException e) {
			log.error("Exception during CMP processing: ", e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (AuthStatusException e) {
			log.error("Exception during CMP processing: ", e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (AuthLoginException e) {
			log.error("Exception during CMP processing: ", e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, e.getMessage());
		} catch (IllegalKeyException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (CADoesntExistsException e) {
			log.error("Exception during CMP processing: ", e);
			resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.WRONG_AUTHORITY, e.getMessage());
		} catch (SignRequestException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (SignRequestSignatureException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (ClassNotFoundException e) {
			log.error("Exception during CMP processing: ", e);
		}
		return resp;
	}
	
}
