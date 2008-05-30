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
package org.ejbca.core.protocol.ws;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.jws.WebService;
import javax.naming.NamingException;
import javax.xml.ws.WebServiceContext;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ApprovedActionAdmin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.RequestMessageUtils;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.HardTokenConstants;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.common.WSConfig;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.PINDataWS;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

import com.novosec.pkix.asn1.crmf.CertRequest;

/**
 * Implementor of the IEjbcaWS interface.
 * Keep this class free of other helper methods, and implement them in the helper classes instead.
 * 
 * @author Philip Vendil
 * $Id$
 */
@WebService
public class EjbcaWS implements IEjbcaWS {
	@Resource
	private WebServiceContext wsContext;	
	
	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;
	
	private static final Logger log = Logger.getLogger(EjbcaWS.class);	
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#editUser(org.ejbca.core.protocol.ws.objects.UserDataVOWS)
	 */	
	public void editUser(UserDataVOWS userdata)
			throws  AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {
		   	    
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		  Admin admin = ejbhelper.getAdmin(wsContext);
		  UserDataVO userdatavo = ejbhelper.convertUserDataVOWS(admin, userdata);
		  
		  int caid = userdatavo.getCAId();
		  ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
		  
		  if(ejbhelper.getUserAdminSession().findUser(admin, userdatavo.getUsername()) != null){
			  log.debug("User " + userdata.getUsername() + " exists, update the userdata." );
			  ejbhelper.getUserAdminSession().changeUser(admin,userdatavo,userdata.getClearPwd());
		  }else{
			  log.debug("New User " + userdata.getUsername() + ", adding userdata." );
			  ejbhelper.getUserAdminSession().addUser(admin,userdatavo,userdata.getClearPwd());
		  }
		}catch(UserDoesntFullfillEndEntityProfile e){
			log.debug("UserDoesntFullfillEndEntityProfile: "+e.getMessage());
			throw e;
	    } catch (ClassCastException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.info("AuthorizationDeniedException: "+e.getMessage());
			throw e;
		} catch (CreateException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			log.error("EJBCA WebService error, editUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, editUser : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}
	
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findUser(org.ejbca.core.protocol.ws.objects.UserMatch)
	 */
	
	public List<UserDataVOWS> findUser(UserMatch usermatch) throws AuthorizationDeniedException, IllegalQueryException, EjbcaException {		
    	ArrayList<UserDataVOWS> retval = null;
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		  Admin admin = ejbhelper.getAdmin(wsContext);
		  Query query = ejbhelper.convertUserMatch(admin, usermatch);		  		  
		  Collection result = ejbhelper.getUserAdminSession().query(admin, query, null,null, MAXNUMBEROFROWS);
		  
		  if(result.size() > 0){
		    retval = new ArrayList<UserDataVOWS>();
		    Iterator iter = result.iterator();
		    for(int i=0; i<result.size();i++){
		    	UserDataVO userdata = (UserDataVO) iter.next();
		    	retval.add(ejbhelper.convertUserDataVO(admin,userdata));
		    }		    
		  }

		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return retval;

	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findCerts(java.lang.String, boolean)
	 */
	
	public List<Certificate> findCerts(String username, boolean onlyValid)
			throws  AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		List<Certificate> retval = null;
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(wsContext);
			ejbhelper.getUserAdminSession().findUser(admin,username);
			
			Collection certs = ejbhelper.getCertStoreSession().findCertificatesByUsername(admin,username);
			
			if(onlyValid){
				certs = ejbhelper.returnOnlyValidCertificates(admin,certs); 
			}
			
			certs = ejbhelper.returnOnlyAuthorizedCertificates(admin,certs);
			
			if(certs.size() > 0){
			  retval = new ArrayList<Certificate>();
			  Iterator iter = certs.iterator();
			  for(int i=0; i < certs.size(); i++){				  					
				  retval.add(new Certificate((java.security.cert.Certificate) iter.next()));
			  }
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
		    log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#crmfRequest(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse crmfRequest(String username, String password,
			String crmf, String hardTokenSN, String responseType)
	throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		return new CertificateResponse(responseType, processCertReq(username, password,
				crmf, REQTYPE_CRMF, hardTokenSN, responseType));
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#spkacRequest(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse spkacRequest(String username, String password,
			String spkac, String hardTokenSN, String responseType)
	throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		return new CertificateResponse(responseType, processCertReq(username, password,
				spkac, REQTYPE_SPKAC, hardTokenSN, responseType));
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#cvcRequest
	 */
	public List<Certificate> cvcRequest(String username, String password, String cvcreq)
			throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException,
			EjbcaException, ApprovalException, WaitingForApprovalException {
		log.debug(">cvcRequest");
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);
		
		// Check if user is revoked
		try {
			UserDataVO user;
			user = ejbhelper.getUserAdminSession().findUser(admin, username);
			// See if this user already exists.
			// We allow renewal of certificates for IS's that are not revoked
			// In that case look for it's last old certificate and try to authenticate the request using an outer signature.
			// If this verification is correct, set status to NEW and continue process the request.
			if (user != null) {
				int status = user.getStatus();
				// If user is revoked, we can not proceed
				if ( (status == UserDataConstants.STATUS_REVOKED) || (status == UserDataConstants.STATUS_HISTORICAL) ) {
					throw new AuthorizationDeniedException("User '"+username+"' is revoked.");
				}
				Collection certs = ejbhelper.getCertStoreSession().findCertificatesByUsername(admin, username);
				// certs contains certificates ordered with last expire date first. Last expire date should be last issued cert
				if (certs != null) {
					log.debug("Found "+certs.size()+" old certificates for user "+username);
					// We will only use the latest cert
					Iterator iterator = certs.iterator(); 
					// We have to iterate over available user certificates, because we don't know which on signed the old one
					// and cv certificates have very coarse grained validity periods so we can't really know which one is the latest one
					// if 2 certificates are issued the same day.
					CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(cvcreq.getBytes()));
					if (parsedObject instanceof CVCAuthenticatedRequest) {
						CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
						CVCPublicKey cvcKey = authreq.getRequest().getCertificateBody().getPublicKey();
			            String algorithm = AlgorithmUtil.getAlgorithmName(cvcKey.getObjectIdentifier());
			            log.debug("Received request has a public key with algorithm: "+algorithm);
						String holderRef = authreq.getRequest().getCertificateBody().getHolderReference().getValue();
						while (iterator.hasNext()) {
							java.security.cert.Certificate cert = (java.security.cert.Certificate)iterator.next();
							try {
								// Only allow renewal if the old certificate is valid
								try {
									CertTools.checkValidity(cert, new Date());
									log.debug("Trying to verify the outer signature with a valid certificate");
									authreq.verify(cert.getPublicKey());
									// Verification succeeded, lets set user status to new, the password as passed in and proceed
									String msg = intres.getLocalizedMessage("cvc.info.renewallowed", CertTools.getFingerprintAsString(cert), username);            	
									log.info(msg);
									ejbhelper.getUserAdminSession().setPassword(admin, username, password);
									ejbhelper.getUserAdminSession().setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
									// If we managed to verify the certificate we will break out of the loop
									log.debug("Verified outer signature");
									// Check to see that the inner signature does not also verify using the old certificate
									// because that means the same keys were used, and that is not allowed according to the EU policy
									CVCertificate innerreq = authreq.getRequest();
									CardVerifiableCertificate innercert = new CardVerifiableCertificate(innerreq);
									try {
										innercert.verify(cert.getPublicKey());										
										msg = intres.getLocalizedMessage("cvc.error.renewsamekeys", holderRef);            	
										log.info(msg);
										throw new AuthorizationDeniedException(msg);
									} catch (SignatureException e) {
									}
									
									break;																		
								} catch (CertificateNotYetValidException e) {
									log.debug("Certificate we try to verify outer signature with is not yet valid");
								} catch (CertificateExpiredException e) {									
									log.debug("Certificate we try to verify outer signature with has expired");
								}
							} catch (InvalidKeyException e) {
								String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef, e.getMessage());            	
								log.debug(msg, e);
							} catch (CertificateException e) {
								String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef, e.getMessage());            	
								log.debug(msg, e);
							} catch (NoSuchAlgorithmException e) {
								String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef, e.getMessage());            	
								log.debug(msg, e);
							} catch (NoSuchProviderException e) {
								String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef, e.getMessage());            	
								log.debug(msg, e);
							} catch (SignatureException e) {
								String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef, e.getMessage());            	
								log.debug(msg, e);
							}
							// if verification failed, continue processing as usual, using the sent in username/password hoping the
							// status is NEW and password is correct.
						}
					}
					// If it is not an authenticated request, with an outer signature, continue processing as usual, 
					// using the sent in username/password hoping the status is NEW and password is correct. 
				}
				// If there are no old certificate, continue processing as usual, using the sent in username/password hoping the
				// status is NEW and password is correct.
			} else {
				// If there are no old user, continue processing as usual... it will fail
				log.debug("No existing user exists with username: "+username);
			}
			
			// Finally generate the certificate (assuming status is NEW and password is correct
			byte[] response = processCertReq(username, password, cvcreq, REQTYPE_CVC, null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
			CertificateResponse ret = new CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE, response);
			byte[] b64cert = ret.getData();
			CVCertificate certObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
			java.security.cert.Certificate iscert = new CardVerifiableCertificate(certObject); 
			ArrayList<Certificate> retval = new ArrayList<Certificate>();
			retval.add(new Certificate((java.security.cert.Certificate)iscert));
			// Get the certificate chain
			if (user != null) {
				int caid = user.getCAId();
				Collection certs = ejbhelper.getSignSession().getCertificateChain(admin, caid);
				Iterator iter = certs.iterator();
				while (iter.hasNext()) {
					java.security.cert.Certificate cert = (java.security.cert.Certificate)iter.next();
					retval.add(new Certificate(cert));
				}
			}
			log.debug("<cvcRequest");
			return retval;
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (ServiceLocatorException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (ParseException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (ConstructionException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NoSuchFieldException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, cvcRequest : ",e);
		    throw new EjbcaException(e.getMessage());
		}		
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs10Request(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse pkcs10Request(String username, String password,
			String pkcs10, String hardTokenSN, String responseType)
			throws AuthorizationDeniedException, NotFoundException,
			EjbcaException {
		
		return new CertificateResponse(responseType, processCertReq(username, password,
			                           pkcs10, REQTYPE_PKCS10, hardTokenSN, responseType));
	}

	private static final int REQTYPE_PKCS10 = 1;
	private static final int REQTYPE_CRMF = 2;
	private static final int REQTYPE_SPKAC = 3;
	private static final int REQTYPE_CVC = 4;
	
	private byte[] processCertReq(String username, String password,
			String req, int reqType, String hardTokenSN, String responseType) throws AuthorizationDeniedException, NotFoundException, EjbcaException{
		byte[] retval = null;

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(wsContext);			  

			// check CAID
			UserDataVO userdata = ejbhelper.getUserAdminSession().findUser(admin,username);
			if(userdata == null){
				throw new NotFoundException("Error: User " + username + " doesn't exist");
			}
			int caid = userdata.getCAId();
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);

			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_CREATECERTIFICATE);

			// Check tokentype
			if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
				throw new EjbcaException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
			}

			PublicKey pubKey = null;
			if (reqType == REQTYPE_PKCS10) {				
				PKCS10RequestMessage pkcs10req=RequestMessageUtils.genPKCS10RequestMessageFromPEM(req.getBytes());
				pubKey = pkcs10req.getRequestPublicKey();
			}
			if (reqType == REQTYPE_SPKAC) {
				// parts copied from request helper.
				byte[] reqBytes = req.getBytes();
				if (reqBytes != null) {
					log.debug("Received NS request: "+new String(reqBytes));
					byte[] buffer = Base64.decode(reqBytes);
					if (buffer == null) {
						return null;
					}
					ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(buffer));
					ASN1Sequence spkacSeq = (ASN1Sequence) in.readObject();
					in.close();
					NetscapeCertRequest nscr = new NetscapeCertRequest(spkacSeq);
					// Verify POPO, we don't care about the challenge, it's not important.
					nscr.setChallenge("challenge");
					if (nscr.verify("challenge") == false) {
						log.debug("POPO verification Failed");
						throw new SignRequestSignatureException("Invalid signature in NetscapeCertRequest, popo-verification failed.");
					}
					log.debug("POPO verification successful");
					pubKey = nscr.getPublicKey();
				}		
			}
			if (reqType == REQTYPE_CRMF) {
				ASN1InputStream in = new ASN1InputStream( Base64.decode(req.getBytes()) );
				ASN1Sequence    crmfSeq = (ASN1Sequence) in.readObject();
				ASN1Sequence reqSeq =  (ASN1Sequence) ((ASN1Sequence) crmfSeq.getObjectAt(0)).getObjectAt(0);
				CertRequest certReq = new CertRequest( reqSeq );
				SubjectPublicKeyInfo pKeyInfo = certReq.getCertTemplate().getPublicKey();
				KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
				KeySpec keySpec = new X509EncodedKeySpec( pKeyInfo.getEncoded() );
				pubKey = keyFact.generatePublic(keySpec);
			}
			if (reqType == REQTYPE_CVC) {
				CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(req.getBytes()));
				// We will handle both the case if the request is an authenticated request, i.e. with an outer signature
				// and when the request is missing the (optional) outer signature.
				CVCertificate cvccert = null;
				if (parsedObject instanceof CVCAuthenticatedRequest) {
					CVCAuthenticatedRequest cvcreq = (CVCAuthenticatedRequest)parsedObject;
					cvccert = cvcreq.getRequest();
				} else {
					cvccert = (CVCertificate)parsedObject;
				}
				pubKey = cvccert.getCertificateBody().getPublicKey();
				// Verify POP on the inner request
				CardVerifiableCertificate cert = new CardVerifiableCertificate(cvccert);
				try {
					cert.verify(pubKey);
				} catch (CertificateException e) {
					log.debug("POPO verification Failed");
					throw new SignRequestSignatureException("Invalid inner signature in CVCRequest, popo-verification failed.");
				}
				log.debug("POPO verification successful");
			}
			if (pubKey != null) {
				retval = getCertResponseFromPublicKey(admin, pubKey, username, password, hardTokenSN, responseType, ejbhelper);
			}
		}catch(AuthorizationDeniedException ade){
			throw ade;
		
		} catch (InvalidKeyException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (IllegalKeyException e) {
			// Don't log a bad error for this (user's key length too small)
			log.debug("EJBCA WebService error, pkcs12Req : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
			log.debug("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (AuthLoginException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CADoesntExistsException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (SignatureException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (InvalidKeySpecException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NoSuchProviderException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (CreateException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());		
		} catch (IOException e) {
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (FinderException e) {
			new NotFoundException(e.getMessage());
		} catch (ParseException e) {
			// CVC error
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (ConstructionException e) {
			// CVC error
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		} catch (NoSuchFieldException e) {
			// CVC error
			log.error("EJBCA WebService error, processCertReq : ",e);
			throw new EjbcaException(e.getMessage());			
		}

		return retval;
	}


	private byte[] getCertResponseFromPublicKey(Admin admin, PublicKey pubKey, String username, String password,
			String hardTokenSN, String responseType, EjbcaWSHelper ejbhelper) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, RemoteException, ServiceLocatorException, CreateException, CertificateEncodingException, SignRequestSignatureException {
		byte[] retval = null;
		java.security.cert.Certificate cert =  ejbhelper.getSignSession().createCertificate(admin,username,password, pubKey);
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)){
			retval = cert.getEncoded();
		}
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)){
			retval = ejbhelper.getSignSession().createPKCS7(admin, cert, false);
		}
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)){
			retval = ejbhelper.getSignSession().createPKCS7(admin, cert, true);
		}


		if(hardTokenSN != null){ 
			ejbhelper.getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,(X509Certificate) cert);				  
		}
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs12Req(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public KeyStore pkcs12Req(String username, String password, String hardTokenSN, String keyspec, String keyalg) throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		KeyStore retval = null;
		
		try{
			  EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			  Admin admin = ejbhelper.getAdmin(wsContext);

			  // check CAID
			  UserDataVO userdata = ejbhelper.getUserAdminSession().findUser(admin,username);
			  if(userdata == null){
				  throw new NotFoundException("Error: User " + username + " doesn't exist");
			  }
			  int caid = userdata.getCAId();
			  ejbhelper.getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.CAPREFIX +caid);

			  ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_CREATECERTIFICATE);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_P12){
				  throw new EjbcaException("Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests");
			  }

			  boolean usekeyrecovery = (ejbhelper.getRAAdminSession().loadGlobalConfiguration(admin)).getEnableKeyRecovery();
			  log.debug("usekeyrecovery: "+usekeyrecovery);
			  boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery &&  (userdata.getStatus() != UserDataConstants.STATUS_KEYRECOVERY);
			  log.debug("userdata.getKeyRecoverable(): "+userdata.getKeyRecoverable());
			  log.debug("userdata.getStatus(): "+userdata.getStatus());
			  log.debug("savekeys: "+savekeys);
			  boolean loadkeys = (userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			  log.debug("loadkeys: "+loadkeys);
			  int endEntityProfileId = userdata.getEndEntityProfileId();
			  EndEntityProfile endEntityProfile = ejbhelper.getRAAdminSession().getEndEntityProfile(admin, endEntityProfileId);
			  boolean reusecertificate = endEntityProfile.getReUseKeyRevoceredCertificate();
			  log.debug("reusecertificate: "+reusecertificate);

			  X509Certificate cert = null;
			  try {
				  GenerateToken tgen = new GenerateToken(false);
				  java.security.KeyStore pkcs12 = tgen.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
				  retval = new KeyStore(pkcs12, password);
				  Enumeration<String> en = pkcs12.aliases();
				  String alias = en.nextElement();
				  cert = (X509Certificate) pkcs12.getCertificate(alias);
			  } catch (Exception e) {
				  log.error("Error generating keystore, pkcs12Req: ", e);
				  throw new EjbcaException(e);
			  }
			  
			  if ( (hardTokenSN != null) && (cert != null) ) {
				  ejbhelper.getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,cert);				  
			  }
			  
			}catch(AuthorizationDeniedException ade){
				throw ade;
			} catch (ClassCastException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CreateException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (ObjectNotFoundException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (AuthStatusException e) {
				// Don't log a bad error for this (user wrong status)
				log.debug("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (AuthLoginException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (IllegalKeyException e) {
				// Don't log a bad error for this (user's key length too small)
				log.debug("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CADoesntExistsException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (RemoteException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
				throw new EjbcaException(e.getMessage());
			} catch (FinderException e) {
				new NotFoundException(e.getMessage());
			}
			return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeCert(java.lang.String, java.lang.String, int)
	 */
	
	public void revokeCert(String issuerDN, String certificateSN, int reason) throws AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(wsContext);

			BigInteger serno = new BigInteger(certificateSN,16);
			String username = ejbhelper.getCertStoreSession().findUsernameByCertSerno(admin,serno,issuerDN);

			// check that admin is autorized to CA
			int caid = CertTools.stringToBCDNString(issuerDN).hashCode();		
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);			  

			if(reason == RevokedCertInfo.NOT_REVOKED){
				java.security.cert.Certificate cert = ejbhelper.getCertStoreSession().findCertificateByIssuerAndSerno(admin, issuerDN, serno);
				if(cert == null){
					throw new NotFoundException("Error: certificate with issuerdn " + issuerDN + " and serial number " + serno + " couldn't be found in database.");
				}
				CertificateInfo certInfo = ejbhelper.getCertStoreSession().getCertificateInfo(admin, CertTools.getCertFingerprintAsString(cert.getEncoded()));
				if(certInfo.getRevocationReason()== RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD){
					ejbhelper.getUserAdminSession().unRevokeCert(admin, serno, issuerDN, username);
				}else{
					throw new EjbcaException("Error: Status is NOT 'certificate hold' for certificate with serial number " + serno + " and issuer DN " + issuerDN);
				}
			}else{			
				ejbhelper.getUserAdminSession().revokeCert(admin,serno, issuerDN, username,  reason);
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, revokeCert : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, revokeCert : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, revokeCert : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, revokeCert : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeUser(java.lang.String, int, boolean)
	 */
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(wsContext);

			// check CAID
			UserDataVO userdata = ejbhelper.getUserAdminSession().findUser(admin,username);
			if(userdata == null){
				throw new NotFoundException("Error: User " + username + " doesn't exist");
			}
			int caid = userdata.getCAId();
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);						
			if (deleteUser) {
				ejbhelper.getUserAdminSession().revokeAndDeleteUser(admin,username,reason);
			} else {
				ejbhelper.getUserAdminSession().revokeUser(admin,username,reason);
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e);
		}  catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (NotFoundException e) {
			throw e;
		} catch (RemoveException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e);
		} catch (CreateException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e);
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#keyRecoverNewest(java.lang.String)
	 */
	public void keyRecoverNewest(String username) throws AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException {
		log.debug(">keyRecoverNewest");
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(wsContext);

            boolean usekeyrecovery = ejbhelper.getRAAdminSession().loadGlobalConfiguration(admin).getEnableKeyRecovery();  
            if(!usekeyrecovery){
				throw new EjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.");
            }   
			UserDataVO userdata = ejbhelper.getUserAdminSession().findUser(admin, username);
			if(userdata == null){
				throw new NotFoundException("Error: User " + username + " doesn't exist.");
			}
			if(ejbhelper.getKeyRecoverySession().isUserMarked(admin, username)){
				// User is already marked for recovery.
				return;                     
			}
			// check CAID
			int caid = userdata.getCAId();
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);						

			// Do the work, mark user for key recovery
			ejbhelper.getKeyRecoverySession().markNewestAsRecoverable(admin, username, userdata.getEndEntityProfileId());

		}  catch (FinderException e) {
			throw new NotFoundException(e.getMessage(), e);
		} catch (CreateException e) {
			log.error("EJBCA WebService error, keyRecoverNewest : ",e);
			throw new EjbcaException(e);
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, keyRecoverNewest : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		log.debug("<keyRecoverNewest");
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeToken(java.lang.String, int)
	 */
	public void revokeToken(String hardTokenSN, int reason)
	throws RemoteException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		revokeToken(ejbhelper.getAdmin(wsContext), hardTokenSN, reason);
	}
	
	private void revokeToken(Admin admin, String hardTokenSN, int reason) throws AuthorizationDeniedException,
			NotFoundException, EjbcaException, AlreadyRevokedException, ApprovalException, WaitingForApprovalException {
		ApprovalException lastApprovalException = null;
		WaitingForApprovalException lastWaitingForApprovalException = null;
		AuthorizationDeniedException lastAuthorizationDeniedException = null;
		AlreadyRevokedException lastAlreadyRevokedException = null;
		boolean success = false;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		try{
			Collection certs = ejbhelper.getHardTokenSession().findCertificatesInHardToken(admin,hardTokenSN);
			Iterator iter = certs.iterator();
			String username = null;
			while(iter.hasNext()){
				X509Certificate next = (X509Certificate) iter.next();
				if(username == null){
					username = ejbhelper.getCertStoreSession().findUsernameByCertSerno(admin,CertTools.getSerialNumber(next),CertTools.getIssuerDN(next));
				}
				
				// check that admin is authorized to CA
				int caid = CertTools.getIssuerDN(next).hashCode();		
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
				if(reason == RevokedCertInfo.NOT_REVOKED){
					String issuerDN = CertTools.getIssuerDN(next);
					BigInteger serno = CertTools.getSerialNumber(next);

					CertificateInfo certInfo = ejbhelper.getCertStoreSession().getCertificateInfo(admin, CertTools.getCertFingerprintAsString(next.getEncoded()));
					if(certInfo.getRevocationReason()== RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD){
						try {
							ejbhelper.getUserAdminSession().unRevokeCert(admin, serno, issuerDN, username);
							success = true;
						} catch (WaitingForApprovalException e) {
							lastWaitingForApprovalException = e;
						} catch (ApprovalException e) {
							lastApprovalException = e;
						} catch(AuthorizationDeniedException e) {
							lastAuthorizationDeniedException = e;
						} catch (AlreadyRevokedException e) {
							lastAlreadyRevokedException = e;
						}
					}else{
						throw new EjbcaException("Error: Status is NOT 'certificate hold' for certificate with serial number " + serno + " and issuer DN " + issuerDN);
					}
				}else{
					try {
						ejbhelper.getUserAdminSession().revokeCert(admin,CertTools.getSerialNumber(next),CertTools.getIssuerDN(next),username,reason);
						success = true;
					} catch (WaitingForApprovalException e) {
						lastWaitingForApprovalException = e;
					} catch (ApprovalException e) {
						lastApprovalException = e;
					} catch(AuthorizationDeniedException e) {
						lastAuthorizationDeniedException = e;
					} catch (AlreadyRevokedException e) {
						lastAlreadyRevokedException = e;
					}
				}
			}
			if (lastWaitingForApprovalException != null ) {
				throw lastWaitingForApprovalException;
			}
			if (lastApprovalException != null) {
				throw lastApprovalException;
			}
			if (!success && lastAuthorizationDeniedException != null) {
				throw lastAuthorizationDeniedException;
			}
			if (!success && lastAlreadyRevokedException != null) {
				throw lastAlreadyRevokedException;
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#checkRevokationStatus(java.lang.String, java.lang.String)
	 */
	
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws   AuthorizationDeniedException, EjbcaException {
		RevokeStatus retval = null;

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		  Admin admin = ejbhelper.getAdmin(wsContext);		  

		  // check that admin is autorized to CA
		  int caid = CertTools.stringToBCDNString(issuerDN).hashCode();		
		  ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
		  
		  RevokedCertInfo certinfo = ejbhelper.getCertStoreSession().isRevoked(admin,issuerDN,new BigInteger(certificateSN,16));
		  if(certinfo != null){
		    retval = new RevokeStatus(certinfo,issuerDN);
		  }
		}catch(AuthorizationDeniedException ade){
			throw ade;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return retval;

	}	

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isAuthorized(java.lang.String)
	 */
	public boolean isAuthorized(String resource) throws EjbcaException{
		boolean retval = false;
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			retval = ejbhelper.getAuthorizationSession().isAuthorized(ejbhelper.getAdmin(wsContext), resource);	
		}catch(AuthorizationDeniedException ade){
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#fetchUserData(java.util.List, java.lang.String)
	 */
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws UserDataSourceException, EjbcaException, AuthorizationDeniedException{
	    
		Admin admin = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		if(WSConfig.isNoAuthOnFetchUserData()){
			admin = ejbhelper.getAdmin(true, wsContext);
			admin = new ApprovedActionAdmin(admin.getAdminInformation().getX509Certificate());
		}else{
			admin = ejbhelper.getAdmin(wsContext);
		}
		
		ArrayList<UserDataSourceVOWS> retval = new ArrayList<UserDataSourceVOWS>();
		
		try {	
			ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();

			Iterator iter = userDataSourceNames.iterator();
			while(iter.hasNext()){
				String name = (String) iter.next();
				int id = ejbhelper.getUserDataSourceSession().getUserDataSourceId(admin, name);
				if(id != 0){
					userDataSourceIds.add(new Integer(id));
				}else{
					log.error("Error User Data Source with name : " + name + " doesn't exist.");
				}
			}

			iter = ejbhelper.getUserDataSourceSession().fetch(admin, userDataSourceIds, searchString).iterator();
			while(iter.hasNext()){
				UserDataSourceVO next = (UserDataSourceVO) iter.next();
				retval.add(new UserDataSourceVOWS(ejbhelper.convertUserDataVO(admin, next.getUserDataVO()),next.getIsFieldModifyableSet()));
			}
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		
        return retval;		
	}		
	
	/**
	 * @throws NamingException 
	 * @throws CreateException 
	 * @throws ApprovalException 
	 * @throws UserDoesntFullfillEndEntityProfile 
	 * @throws ApprovalRequestExpiredException 
	 * @throws ClassCastException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#genTokenCertificates(org.ejbca.core.protocol.ws.objects.UserDataVOWS, java.util.List, org.ejbca.core.protocol.ws.objects.HardTokenDataWS)
	 */
	
	public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userDataWS, List<TokenCertificateRequestWS> tokenRequests, HardTokenDataWS hardTokenDataWS, boolean overwriteExistingSN, boolean revocePreviousCards) throws AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException,UserDoesntFullfillEndEntityProfile, ApprovalException, EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException {
		ArrayList<TokenCertificateResponseWS> retval = new ArrayList<TokenCertificateResponseWS>();

		Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(true, wsContext);
		int endEntityProfileId = 0;
		boolean hardTokenExists = false;
		boolean userExists = false;
		
		ApprovalRequest ar = null;
		boolean approvalSuccessfullStep1 = false;
		boolean isRejectedStep1 = false;

		// Get Significant user Id
		CAInfo significantcAInfo = null;
		try {
			significantcAInfo = ejbhelper.getCAAdminSession().getCAInfo(intAdmin, userDataWS.getCaName());
		} catch (Exception e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		}
		if(significantcAInfo == null){
			throw new EjbcaException("Error the given CA : " + userDataWS.getCaName() + " couldn't be found.");
		}
		
		IUserAdminSessionRemote usersess = null;
		try{
			usersess = ejbhelper.getUserAdminSession();
			userExists = usersess.existsUser(intAdmin, userDataWS.getUsername());	    
			UserDataVO userDataVO = null;
			if(userExists){
				userDataVO = ejbhelper.getUserAdminSession().findUser(intAdmin, userDataWS.getUsername());
				endEntityProfileId = userDataVO.getEndEntityProfileId();
			}else{
				endEntityProfileId = ejbhelper.getRAAdminSession().getEndEntityProfileId(intAdmin, userDataWS.getEndEntityProfileName());	    	  
				if(endEntityProfileId == 0){
					throw new EjbcaException("Error given end entity profile : " + userDataWS.getEndEntityProfileName() +" couldn't be found");
				}
			}
			
			
			if(ejbhelper.isAdmin(wsContext)){			
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_CREATECERTIFICATE);
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.HARDTOKEN_ISSUEHARDTOKENS);
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + significantcAInfo.getCAId());
				if(userExists){
					ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_EDITENDENTITY);					
					endEntityProfileId = userDataVO.getEndEntityProfileId();
					ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.EDIT_RIGHTS);
					if(overwriteExistingSN){
						ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_REVOKEENDENTITY);
						ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.REVOKE_RIGHTS);
					}
				}else{
					ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_CREATEENDENTITY);
					ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.CREATE_RIGHTS);
					if(overwriteExistingSN){
						ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_REVOKEENDENTITY);
						ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.REVOKE_RIGHTS);				       
					}
				}

			}else{
				if(WSConfig.isApprovalGenTokenCertificates()){
					ar = new GenerateTokenApprovalRequest(userDataWS.getUsername(), userDataWS.getSubjectDN(),  hardTokenDataWS.getLabel(),admin,null,WSConfig.getNumberOfWSApprovals(),significantcAInfo.getCAId(),endEntityProfileId);
					int status = ApprovalDataVO.STATUS_REJECTED; 					
					try{
					  status = ejbhelper.getApprovalSession().isApproved(admin, ar.generateApprovalId(), 1);
					  approvalSuccessfullStep1 =  status == ApprovalDataVO.STATUS_APPROVED;
					  if(approvalSuccessfullStep1){
						  ApprovalDataVO approvalDataVO = ejbhelper.getApprovalSession().findNonExpiredApprovalRequest(intAdmin, ar.generateApprovalId());
						  String originalDN = ((GenerateTokenApprovalRequest) approvalDataVO.getApprovalRequest()).getDN();
						  userDataWS.setSubjectDN(originalDN); // replace requested DN with original DN to make sure nothing have changed.
					  }
					  isRejectedStep1 = status == ApprovalDataVO.STATUS_REJECTED;
					  if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
					     || status == ApprovalDataVO.STATUS_EXPIRED){
						  throw new ApprovalException("");
					  }
					}catch(ApprovalException e){
						ejbhelper.getApprovalSession().addApprovalRequest(admin, ar);
						throw new WaitingForApprovalException("Approval request with id " + ar.generateApprovalId() + " have been added for approval.",ar.generateApprovalId());
					}
				}else{
					throw new AuthorizationDeniedException();
				}
			}
		} catch (FinderException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} 

		if(ar != null && isRejectedStep1){
			throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " have been rejected.");
		}
		
		if(ar != null && !approvalSuccessfullStep1){
			throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
		}
		
		if(ar != null){
			admin = new ApprovedActionAdmin(admin.getAdminInformation().getX509Certificate());
		}
		
		ArrayList<java.security.cert.Certificate> genCertificates = new ArrayList<java.security.cert.Certificate>();
		try {
			hardTokenExists = ejbhelper.getHardTokenSession().existsHardToken(admin, hardTokenDataWS.getHardTokenSN());
			if(hardTokenExists){
				if(overwriteExistingSN){
					// fetch all old certificates and revoke them.
					Collection currentCertificates = ejbhelper.getHardTokenSession().findCertificatesInHardToken(admin, hardTokenDataWS.getHardTokenSN());
					HardTokenData currentHardToken = ejbhelper.getHardTokenSession().getHardToken(admin, hardTokenDataWS.getHardTokenSN(), false);
					Iterator iter = currentCertificates.iterator();
					while(iter.hasNext()){
						java.security.cert.X509Certificate nextCert = (java.security.cert.X509Certificate) iter.next();
						try {
							usersess.revokeCert(admin, CertTools.getSerialNumber(nextCert), CertTools.getIssuerDN(nextCert), currentHardToken.getUsername(), RevokedCertInfo.REVOKATION_REASON_SUPERSEDED);
						} catch (AlreadyRevokedException e) {
							// Ignore previously revoked certificates
						} catch (FinderException e) {
							throw new EjbcaException("Error revoking old certificate, the user : " + currentHardToken.getUsername() + " of the old certificate couldn't be found in database.");
						} 
					}

				}else{
					throw new HardTokenExistsException("Error hard token with sn " + hardTokenDataWS.getHardTokenSN() + " already exists.");
				}

			}


			if(revocePreviousCards){
				List<HardTokenDataWS> htd = getHardTokenDatas(admin,userDataWS.getUsername(), false, true);
				Iterator htdIter = htd.iterator();

				while(htdIter.hasNext()) {
					HardTokenDataWS toRevoke = (HardTokenDataWS)htdIter.next();
					try{
						if(hardTokenDataWS.getLabel().equals(HardTokenConstants.LABEL_TEMPORARYCARD)){
							if(WSConfig.isSetMSLogonOnHold()){
								// Set all certificates on hold
								revokeToken(admin, toRevoke.getHardTokenSN(), RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
							}else{
								// Token have extended key usage MS Logon, don't revoke it
								Iterator revokeCerts = ejbhelper.getHardTokenSession().findCertificatesInHardToken(admin, toRevoke.getHardTokenSN()).iterator();

								while(revokeCerts.hasNext()){
									X509Certificate next = (X509Certificate) revokeCerts.next();							 
									try{
										if(!next.getExtendedKeyUsage().contains(CertificateProfile.EXTENDEDKEYUSAGEOIDSTRINGS[CertificateProfile.SMARTCARDLOGON])){
											revokeCert(CertTools.getIssuerDN(next), CertTools.getSerialNumber(next).toString(16), RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
										}
									}catch(CertificateParsingException e){
										log.error(e);
									}
								}
							}


						}else{
							revokeToken(admin, toRevoke.getHardTokenSN(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
						}
					}catch(AlreadyRevokedException e){
						// Do nothing
					}
				}
			}
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		}
		
		try{
			// Check if the userdata exist and edit/add it depending on which
			String password = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(8, 8);
			UserDataVO userData = ejbhelper.convertUserDataVOWS(admin, userDataWS);
			userData.setPassword(password);
			if(userExists){
				ejbhelper.getUserAdminSession().changeUser(admin, userData, true);
			}else{
				ejbhelper.getUserAdminSession().addUser(admin, userData, true);
			}

			Date bDate = new Date(System.currentTimeMillis() - (10 * 60 * 1000));
			
			Iterator<TokenCertificateRequestWS> iter = tokenRequests.iterator();
			while(iter.hasNext()){
				TokenCertificateRequestWS next = iter.next();

				int certificateProfileId = ejbhelper.getCertStoreSession().getCertificateProfileId(admin, next.getCertificateProfileName());
				if(certificateProfileId == 0){
					throw new EjbcaException("Error the given Certificate Profile : " + next.getCertificateProfileName() + " couldn't be found.");
				}
				
				Date eDate = null;
				
				if(next.getValidityIdDays() != null ){
					try{
						long validity = Long.parseLong(next.getValidityIdDays());
						eDate = new Date(System.currentTimeMillis() + (validity  * 3600 *24 * 1000));
					}catch (NumberFormatException e){
						throw new EjbcaException("Error : Validity in Days must be a number");
					}
				}
				
				CAInfo cAInfo = ejbhelper.getCAAdminSession().getCAInfo(admin, next.getCAName());
				if(cAInfo == null){
					throw new EjbcaException("Error the given CA : " + next.getCAName() + " couldn't be found.");
				}

				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + cAInfo.getCAId());
				if(next.getType() == HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST){						
					userData.setCertificateProfileId(certificateProfileId);
					userData.setCAId(cAInfo.getCAId());
					userData.setPassword(password);
					userData.setStatus(UserDataConstants.STATUS_NEW);
					ejbhelper.getUserAdminSession().changeUser(admin, userData, false);
					PKCS10RequestMessage pkcs10req = new PKCS10RequestMessage(next.getPkcs10Data());
					java.security.cert.Certificate cert;
					if(eDate == null){
					    cert =  ejbhelper.getSignSession().createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey());
					}else{
						cert =  ejbhelper.getSignSession().createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey(), -1, bDate, eDate);
					}
					
					genCertificates.add(cert);
					retval.add(new TokenCertificateResponseWS(new Certificate(cert)));
				}else
					if(next.getType() == HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST){

						if(!next.getTokenType().equals(HardTokenConstants.TOKENTYPE_PKCS12)){
							throw new EjbcaException("Unsupported Key Store Type : " + next.getTokenType() + " only " + HardTokenConstants.TOKENTYPE_PKCS12 + " is supported");
						}
						KeyPair keys = KeyTools.genKeys(next.getKeyspec(), next.getKeyalg());							  
						userData.setCertificateProfileId(certificateProfileId);
						userData.setCAId(cAInfo.getCAId());
						userData.setPassword(password);
						userData.setStatus(UserDataConstants.STATUS_NEW);
						ejbhelper.getUserAdminSession().changeUser(admin, userData, true);
						X509Certificate cert;
						if(eDate == null){
						    cert =  (X509Certificate) ejbhelper.getSignSession().createCertificate(admin,userData.getUsername(),password, keys.getPublic());
						}else{
							cert =  (X509Certificate) ejbhelper.getSignSession().createCertificate(admin,userData.getUsername(),password, keys.getPublic(), -1, bDate, eDate);
						}
						
						genCertificates.add(cert);      
						// Generate Keystore
						// Fetch CA Cert Chain.	        
						Collection chain =  ejbhelper.getCAAdminSession().getCAInfo(admin, cAInfo.getCAId()).getCertificateChain();
						String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
						if (alias == null){
							alias = userData.getUsername();
						}	      	      
						java.security.KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

						retval.add(new TokenCertificateResponseWS(new KeyStore(pkcs12, userDataWS.getPassword())));
					}else{
						throw new EjbcaException("Error in request, only REQUESTTYPE_PKCS10_REQUEST and REQUESTTYPE_KEYSTORE_REQUEST are supported token requests.");
					}
			}

		}catch(Exception e){
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} finally{
			try {
				usersess.setUserStatus(admin, userDataWS.getUsername(), UserDataConstants.STATUS_GENERATED);
			} catch (FinderException e) {
				log.error("EJBCA WebService error, genTokenCertificates : ",e);
				throw new EjbcaException(e.getMessage());
			} catch (RemoteException e) {
				log.error("EJBCA WebService error, genTokenCertificates : ",e);
				throw new EjbcaException(e.getMessage());
			} 
		}

		// Add hard token data
		HardToken hardToken;
		String signatureInitialPIN = "";
		String signaturePUK = "";
		String basicInitialPIN = "";
		String basicPUK = "";
		Iterator<PINDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
		while(iter.hasNext()){
			PINDataWS pinData = iter.next();
			switch(pinData.getType()){
			case HardTokenConstants.PINTYPE_BASIC :
				basicInitialPIN = pinData.getInitialPIN();
				basicPUK = pinData.getPUK(); 
				break;
			case HardTokenConstants.PINTYPE_SIGNATURE :
				signatureInitialPIN = pinData.getInitialPIN();
				signaturePUK = pinData.getPUK();
				break;
			default :
				throw new EjbcaException("Unsupported PIN Type " + pinData.getType());
			}
		}
		int tokenType = SwedishEIDHardToken.THIS_TOKENTYPE;
		switch (hardTokenDataWS.getTokenType()){
		case HardTokenConstants.TOKENTYPE_SWEDISHEID :
			hardToken = new SwedishEIDHardToken(basicInitialPIN,basicPUK,signatureInitialPIN,signaturePUK,0);	
			break;
		case HardTokenConstants.TOKENTYPE_ENHANCEDEID :
			hardToken = new EnhancedEIDHardToken(signatureInitialPIN,signaturePUK,basicInitialPIN,basicPUK,false,0);
			tokenType = EnhancedEIDHardToken.THIS_TOKENTYPE;
			break;
		default:
			throw new EjbcaException("Unsupported Token Type : " + hardTokenDataWS.getTokenType());

		}

		hardToken.setLabel(hardTokenDataWS.getLabel());
		try {
			if(overwriteExistingSN){
				if(hardTokenExists){
					try {
						ejbhelper.getHardTokenSession().removeHardToken(admin, hardTokenDataWS.getHardTokenSN());
					} catch (HardTokenDoesntExistsException e) {
						log.error("EJBCA WebService error, genTokenCertificates : ",e);
						throw new EjbcaException(e.getMessage());
					}
				}
			}
			ejbhelper.getHardTokenSession().addHardToken(admin, hardTokenDataWS.getHardTokenSN(), userDataWS.getUsername(), significantcAInfo.getSubjectDN(), tokenType, hardToken, genCertificates, hardTokenDataWS.getCopyOfSN());

			if(ar!= null){
				ejbhelper.getApprovalSession().markAsStepDone(admin, ar.generateApprovalId(), GenerateTokenApprovalRequest.STEP_1_GENERATETOKEN);
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} 

		return retval; 	
	}
	



	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#existsHardToken(java.lang.String)
	 */
	public boolean existsHardToken(String hardTokenSN) throws EjbcaException{
		boolean retval = true;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		try {
			retval = ejbhelper.getHardTokenSession().existsHardToken(ejbhelper.getAdmin(wsContext), hardTokenSN);
		} catch (CreateException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
			throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}

	/**
	 * @throws ApprovalRequestExpiredException 
	 * @throws WaitingForApprovalException 
	 * @throws ApprovalRequestExecutionException 
	 * @throws ApprovalException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenData(java.lang.String)
	 */
	public HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates) throws AuthorizationDeniedException, HardTokenDoesntExistsException, EjbcaException,  ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException{
		HardTokenDataWS retval = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(true, wsContext);
		ApprovalRequest ar = null;
		boolean isApprovedStep0 = false;
		boolean isRejectedStep0 = false;

		HardTokenData hardTokenData = null;
		try{
			hardTokenData = ejbhelper.getHardTokenSession().getHardToken(admin, hardTokenSN, viewPUKData);
			if(hardTokenData == null){
				throw new HardTokenDoesntExistsException("Error, hard token with SN " + hardTokenSN + " doesn't exist.");
			}
			ejbhelper.isAuthorizedToHardTokenData(admin, hardTokenData.getUsername(), viewPUKData);
		}catch(AuthorizationDeniedException e){
			boolean genNewRequest = false;
			if(WSConfig.isApprovalGetHardTokenData() || WSConfig.isApprovalGetHardTokenData()){
				// Check Approvals
				// Exists an GenTokenCertificates
				try {
					Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
					UserDataVO userData = ejbhelper.getUserAdminSession().findUser(intAdmin, hardTokenData.getUsername());
					ar = new GenerateTokenApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenData.getHardToken().getLabel(),admin,null,WSConfig.getNumberOfWSApprovals(),userData.getCAId(),userData.getEndEntityProfileId());
					int status = ApprovalDataVO.STATUS_REJECTED; 					
					try{
					  if(!WSConfig.isApprovalGenTokenCertificates()){
						  throw new ApprovalException("");
					  }
					  status = ejbhelper.getApprovalSession().isApproved(admin, ar.generateApprovalId(), 0);
					  isApprovedStep0 =  status == ApprovalDataVO.STATUS_APPROVED;
					  
					  if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
							  || status == ApprovalDataVO.STATUS_EXPIRED
							  || status == ApprovalDataVO.STATUS_REJECTED){
						  throw new ApprovalException("");
					  }
					}catch(ApprovalException e2){
						// GenTokenCertificates approval doesn't exists, try a getHardTokenData request
						if(!WSConfig.isApprovalGetHardTokenData()){
							  throw new AuthorizationDeniedException("JaxWS isn't configured for getHardTokenData approvals.");
						}
						ar = new ViewHardTokenDataApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenSN, true,admin,null,WSConfig.getNumberOfWSApprovals(),userData.getCAId(),userData.getEndEntityProfileId());
						try{
						  status = ejbhelper.getApprovalSession().isApproved(admin, ar.generateApprovalId());
						  isApprovedStep0 = status == ApprovalDataVO.STATUS_APPROVED;
						  isRejectedStep0 =  status == ApprovalDataVO.STATUS_REJECTED;
						  if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED 
								     || status == ApprovalDataVO.STATUS_EXPIRED){
							  throw new ApprovalException("");
						  }
						}catch(ApprovalException e3){
							genNewRequest = true; 
						}catch(ApprovalRequestExpiredException e3){
							genNewRequest = true;
						}
						if(genNewRequest){
                            //	Add approval Request
							try{
								ejbhelper.getApprovalSession().addApprovalRequest(admin, ar);
							  throw new WaitingForApprovalException("Adding approval to view hard token data with id " + ar.generateApprovalId(), ar.generateApprovalId());
							}catch(ApprovalException e4){
								throw new EjbcaException(e4);
							}
						}
					}		
				} catch (FinderException e1) {
					log.error("EJBCA WebService error, getHardTokenData : ",e1);
					throw new EjbcaException(e1);
				} catch (CreateException e1) {
					log.error("EJBCA WebService error, getHardTokenData : ",e1);
					throw new EjbcaException(e1);
				} catch (RemoteException e1) {
					log.error("EJBCA WebService error, getHardTokenData : ",e1);
					throw new EjbcaException(e1.getMessage());
				}
			}else{
				throw e;
			}
		} catch (CreateException e1) {
			log.error("EJBCA WebService error, getHardTokenData : ",e1);
			throw new EjbcaException(e1);
		} catch (RemoteException e1) {
			log.error("EJBCA WebService error, getHardTokenData : ",e1);
			throw new EjbcaException(e1.getMessage());
		}
		
		if(ar != null && isRejectedStep0){
			throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " have been rejected.");
		}
		
		if(ar != null && ! isApprovedStep0){
			throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
		}
		
		try {
			Collection certs = ejbhelper.getHardTokenSession().findCertificatesInHardToken(admin, hardTokenSN);

			if(onlyValidCertificates){
				certs = ejbhelper.returnOnlyValidCertificates(admin, certs);
			}

			retval = ejbhelper.convertHardTokenToWS(hardTokenData,certs,viewPUKData);		

			if(ar != null){
				try {
					ejbhelper.getApprovalSession().markAsStepDone(admin, ar.generateApprovalId(), 0);
				} catch (ApprovalException e) {
					throw new EjbcaException(e);
				}
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} 

		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenDatas(java.lang.String)
	 */
	public List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates) throws AuthorizationDeniedException, EjbcaException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		return getHardTokenDatas(ejbhelper.getAdmin(wsContext),username, viewPUKData, onlyValidCertificates);
	}
	
	private List<HardTokenDataWS> getHardTokenDatas(Admin admin, String username, boolean viewPUKData, boolean onlyValidCertificates) throws AuthorizationDeniedException, EjbcaException{
		List<HardTokenDataWS> retval = new  ArrayList<HardTokenDataWS>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		try {
			ejbhelper.isAuthorizedToHardTokenData(admin, username, viewPUKData);

			Collection<?> hardtokens = ejbhelper.getHardTokenSession().getHardTokens(admin, username, viewPUKData);
			Iterator iter = hardtokens.iterator();
			while(iter.hasNext()){
				HardTokenData next = (HardTokenData) iter.next();
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + next.getSignificantIssuerDN().hashCode());
				Collection certs = ejbhelper.getHardTokenSession().findCertificatesInHardToken(admin, next.getTokenSN());
				if(onlyValidCertificates){
					certs = ejbhelper.returnOnlyValidCertificates(admin, certs);
				}
				retval.add(ejbhelper.convertHardTokenToWS(next,certs, viewPUKData));
			}
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getHardTokenData : ",e);
			throw new EjbcaException(e.getMessage());
		} 

		return retval;
	}





	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#republishCertificate(java.lang.String, java.lang.String)
	 */
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws AuthorizationDeniedException, PublisherException, EjbcaException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);

		try{
			String bcIssuerDN = CertTools.stringToBCDNString(issuerDN);
			CertReqHistory certreqhist = ejbhelper.getCertStoreSession().getCertReqHistory(admin,new BigInteger(serialNumberInHex,16), bcIssuerDN);
			if(certreqhist == null){
				throw new PublisherException("Error: the  certificate with  serialnumber : " + serialNumberInHex +" and issuerdn " + issuerDN + " couldn't be found in database.");
			}

			ejbhelper.isAuthorizedToRepublish(admin, certreqhist.getUsername(),bcIssuerDN.hashCode());

			if(certreqhist != null){
				CertificateProfile certprofile = ejbhelper.getCertStoreSession().getCertificateProfile(admin,certreqhist.getUserDataVO().getCertificateProfileId());
				java.security.cert.Certificate cert = ejbhelper.getCertStoreSession().findCertificateByFingerprint(admin, certreqhist.getFingerprint());
				if(certprofile != null){
					CertificateInfo certinfo = ejbhelper.getCertStoreSession().getCertificateInfo(admin, certreqhist.getFingerprint());
					if(certprofile.getPublisherList().size() > 0){
						if(ejbhelper.getPublisherSession().storeCertificate(admin, certprofile.getPublisherList(), cert, certreqhist.getUserDataVO().getUsername(), certreqhist.getUserDataVO().getPassword(),
								certinfo.getCAFingerprint(), certinfo.getStatus() , certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certreqhist.getUserDataVO().getExtendedinformation())){
						}else{
							throw new PublisherException("Error: publication failed to at least one of the defined publishers.");
						}
					}else{
						throw new PublisherException("Error no publisher defined for the given certificate.");
					}

				}else{
					throw new PublisherException("Error : Certificate profile couldn't be found for the given certificate.");
				}	  
			}
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#customLog(int, String, String)
	 */
	public void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg) throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);

		try{
			int event = LogConstants.EVENT_ERROR_CUSTOMLOG;
			switch (level) {
			case IEjbcaWS.CUSTOMLOG_LEVEL_ERROR:
				break;
			case IEjbcaWS.CUSTOMLOG_LEVEL_INFO:
				event = LogConstants.EVENT_INFO_CUSTOMLOG;
				break;
			default:
				throw new EjbcaException("Illegal level "+ level + " sent to custonLog call.");			
			}

			java.security.cert.Certificate logCert = null;
			if(certificate != null){
				logCert = CertificateHelper.getCertificate(certificate.getCertificateData());
			}

			int caId = admin.getCaId();
			if(cAName  != null){
				CAInfo cAInfo = ejbhelper.getCAAdminSession().getCAInfo(admin, cAName);
				if(cAInfo == null){
					throw new EjbcaException("Error given CA Name : " + cAName + " doesn't exists.");
				}
				caId = cAInfo.getCAId();
			}

			String comment = type + " : " + msg;
			ejbhelper.getLogSession().log(admin, caId, LogConstants.MODULE_CUSTOM, new Date(), username, (X509Certificate) logCert, event, comment);
		} catch (CertificateException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, customLog : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#deleteUserDataFromSource(List, String, boolean)
	 */
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException {
		boolean ret = false;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		try {

			Admin admin = ejbhelper.getAdmin(wsContext);
			ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();
			Iterator<String> iter = userDataSourceNames.iterator();
			while(iter.hasNext()){
				String nextName = iter.next();
				int id = ejbhelper.getUserDataSourceSession().getUserDataSourceId(admin, nextName);
				if(id == 0){
					throw new UserDataSourceException("Error: User Data Source with name : " + nextName + " couldn't be found, aborting operation.");
				}
				userDataSourceIds.add(new Integer(id));
			}
			ret = ejbhelper.getUserDataSourceSession().removeUserData(admin, userDataSourceIds, searchString, removeMultipleMatch);
		} catch (CreateException e) {
			log.error("EJBCA WebService error, deleteUserDataFromSource : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, deleteUserDataFromSource : ",e);
			throw new EjbcaException(e.getMessage());
		} 

		return ret; 
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isApproved(int)
	 */
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		int retval = 0;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();

		try {
			retval = ejbhelper.getApprovalSession().isApproved(ejbhelper.getAdmin(true, wsContext), approvalId);
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getCertificate(String, String)
	 */
	public Certificate getCertificate(String certSNinHex, String issuerDN) throws AuthorizationDeniedException, EjbcaException {
		Certificate retval = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(true, wsContext);
		String bcString = CertTools.stringToBCDNString(issuerDN);
		try {
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWCERTIFICATE);
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + bcString.hashCode());

			java.security.cert.Certificate cert = ejbhelper.getCertStoreSession().findCertificateByIssuerAndSerno(admin, issuerDN, new BigInteger(certSNinHex,16));
			if(cert != null){
				retval = new Certificate(cert);
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCAs()
	 */
	public NameAndId[] getAvailableCAs() throws EjbcaException, AuthorizationDeniedException {
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(true, wsContext);
		try {
			Collection<Integer> caids = ejbhelper.getCAAdminSession().getAvailableCAs(admin);
			HashMap map = ejbhelper.getCAAdminSession().getCAIdToNameMap(admin);
			for (Integer id : caids ) {
				String name = (String)map.get(id);
				if (name != null) {
					ret.put(name, id);
				}
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getAvailableCAs : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getAvailableCAs : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return ejbhelper.convertTreeMapToArray(ret);
	}

    /**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAuthorizedEndEntityProfiles()
	 */
	public NameAndId[] getAuthorizedEndEntityProfiles()
			throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		try {
			Collection<Integer> ids = ejbhelper.getRAAdminSession().getAuthorizedEndEntityProfileIds(admin);
			HashMap<Integer,String> idtonamemap = ejbhelper.getRAAdminSession().getEndEntityProfileIdToNameMap(admin);			
			for (Integer id : ids) {
				ret.put(idtonamemap.get(id), id);
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getAuthorizedEndEntityProfiles : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getAuthorizedEndEntityProfiles : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		return ejbhelper.convertTreeMapToArray(ret);
	}

    /**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCertificateProfiles()
	 */
	public NameAndId[] getAvailableCertificateProfiles(int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		try {
			EndEntityProfile profile = ejbhelper.getRAAdminSession().getEndEntityProfile(admin, entityProfileId);
			String[] availablecertprofilesId = profile.getValue(EndEntityProfile.AVAILCERTPROFILES,0).split(EndEntityProfile.SPLITCHAR);
			for (String id : availablecertprofilesId) {
				int i = Integer.parseInt(id);
				ret.put(ejbhelper.getCertStoreSession().getCertificateProfileName(admin,i), i);
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getCertificateProfiles : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getCertificateProfiles : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return  ejbhelper.convertTreeMapToArray(ret);
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCAsInProfile()
	 */
	public NameAndId[] getAvailableCAsInProfile(int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Admin admin = ejbhelper.getAdmin(wsContext);
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		try {
			EndEntityProfile profile = ejbhelper.getRAAdminSession().getEndEntityProfile(admin, entityProfileId);
			Collection<String> cas = profile.getAvailableCAs(); // list of CA ids available in profile
			HashMap<Integer,String> map = ejbhelper.getCAAdminSession().getCAIdToNameMap(admin);
			for (String id : cas ) {
				Integer i = Integer.valueOf(id);
				String name = (String)map.get(i);
				if (name != null) {
					ret.put(name, i);
				}
			}
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getCas : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, getCas : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		return ejbhelper.convertTreeMapToArray(ret);
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#createCRL(String)
	 */
	public void createCRL(String caname) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		try {
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			Admin admin = ejbhelper.getAdmin(true, wsContext);
			CAInfo info = ejbhelper.getCAAdminSession().getCAInfo(admin, caname);
			ejbhelper.getCrlSession().run(admin, info.getSubjectDN());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}

}
