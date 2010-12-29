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

package org.ejbca.core.ejb.ra;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.WrongTokenTypeException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.SimpleRequestMessage;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.RequestMessageUtils;

import com.novosec.pkix.asn1.crmf.CertRequest;

/**
 * Combines EditUser (RA) with CertReq (CA) methods using transactions.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 * 
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateRequestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateRequestSessionBean implements CertificateRequestSessionRemote, CertificateRequestSessionLocal {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CertificateRequestSessionBean.class);
    
    @EJB
    private AuthenticationSessionLocal authenticationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private RaAdminSessionLocal raAdminSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private SignSessionLocal signSession;
    @Resource
    private SessionContext sessionContext;

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request, base64 encoded binary request, in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 */
	public byte[] processCertReq(Admin admin, UserDataVO userdata, String req, int reqType,
			String hardTokenSN, int responseType) throws CADoesntExistsException,
			AuthorizationDeniedException, NotFoundException, InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
			SignatureException, IOException, ObjectNotFoundException, CreateException,
			CertificateException, UserDoesntFullfillEndEntityProfile,
			ApprovalException,
			EjbcaException {
		byte[] retval = null;

		// Check tokentype
		if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
			throw new WrongTokenTypeException ("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
		}
		// This is the secret sauce, do the end entity handling automagically here before we get the cert
		addOrEditUser(admin, userdata, false, true);
		// Process request
		try {
			String password = userdata.getPassword();
			String username = userdata.getUsername();
			IRequestMessage imsg = null;
			if (reqType == SecConst.CERT_REQ_TYPE_PKCS10) {				
				IRequestMessage pkcs10req = RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
				PublicKey pubKey = pkcs10req.getRequestPublicKey();
				imsg = new SimpleRequestMessage(pubKey, username, password);
			} else if (reqType == SecConst.CERT_REQ_TYPE_SPKAC) {
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
					PublicKey pubKey = nscr.getPublicKey();
					imsg = new SimpleRequestMessage(pubKey, username, password);
				}		
			} else if (reqType == SecConst.CERT_REQ_TYPE_CRMF) {
				byte[] request = Base64.decode(req.getBytes());
				ASN1InputStream in = new ASN1InputStream(request);
				ASN1Sequence    crmfSeq = (ASN1Sequence) in.readObject();
				ASN1Sequence reqSeq =  (ASN1Sequence) ((ASN1Sequence) crmfSeq.getObjectAt(0)).getObjectAt(0);
				CertRequest certReq = new CertRequest( reqSeq );
				SubjectPublicKeyInfo pKeyInfo = certReq.getCertTemplate().getPublicKey();
				KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
				KeySpec keySpec = new X509EncodedKeySpec( pKeyInfo.getEncoded() );
				PublicKey pubKey = keyFact.generatePublic(keySpec); // just check it's ok
				imsg = new SimpleRequestMessage(pubKey, username, password);
				// a simple crmf is not a complete PKI message, as desired by the CrmfRequestMessage class
				//PKIMessage msg = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(request)).readObject());
				//CrmfRequestMessage reqmsg = new CrmfRequestMessage(msg, null, true, null);
				//imsg = reqmsg;
			}
			if (imsg != null) {
				retval = getCertResponseFromPublicKey(admin, imsg, hardTokenSN, responseType, userdata);
			}
		} catch (NotFoundException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeyException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchAlgorithmException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeySpecException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchProviderException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (SignatureException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (IOException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (CertificateException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (EjbcaException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		}
		return retval;
	}

	/**
	 * Edits or adds a user and generates a certificate for that user in a single transaction.
     * Username and password in userdata and req message must match.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a certificate
	 * @param req is the certificate request, base64 encoded binary request, in the format specified in the reqType parameter
	 * @param reqType is one of SecConst.CERT_REQ_TYPE_..
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 * @throws EjbcaException 
	 * @throws UserDoesntFullfillEndEntityProfile 
	 * @throws AuthorizationDeniedException 
	 * @throws PersistenceException 
	 * @throws EjbcaException 
	 */
	public IResponseMessage processCertReq(Admin admin, UserDataVO userdata, IRequestMessage req, Class responseClass) throws PersistenceException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException {
		
		// Check tokentype
		if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
			throw new WrongTokenTypeException ("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
		}
		// This is the secret sauce, do the end entity handling automagically here before we get the cert
		addOrEditUser(admin, userdata, false, true);
		IResponseMessage retval = null;
		try {
			retval = signSession.createCertificate(admin, req, responseClass, userdata);
		} catch (NotFoundException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (EjbcaException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		}
		return retval;
	}
	
	/**
	 * @param admin
	 * @param userdata
	 * @param caid
	 * @param username
	 * @throws AuthorizationDeniedException
	 * @throws WrongTokenTypeException
	 * @throws UserDoesntFullfillEndEntityProfile
	 * @throws ApprovalException
	 * @throws PersistenceException
	 * @throws CADoesntExistsException if userdata.caId is not a valid caid. This is checked in editUser or addUserFromWS
	 * @throws EjbcaException 
	 */
	private void addOrEditUser(Admin admin, UserDataVO userdata, boolean clearpwd, boolean fromwebservice) throws AuthorizationDeniedException,
			UserDoesntFullfillEndEntityProfile, ApprovalException,
			PersistenceException, CADoesntExistsException, EjbcaException {
		
		int caid = userdata.getCAId();
		if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX +caid)) {
		    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.CAPREFIX +caid, null);
		}
		if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
		    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE, null);
		}
		// First we need to fetch the CA configuration to see if we save UserData, if not, we still run addUserFromWS to
		// get all the proper authentication checks for CA and end entity profile.
		boolean useUserStorage = caAdminSession.getCAInfo(admin, caid).isUseUserStorage();
		// Add or edit user
		try {
			String username = userdata.getUsername();
			if (useUserStorage && userAdminSession.existsUser(admin, username)) {
				if (log.isDebugEnabled()) {
					log.debug("User " + username + " exists, update the userdata. New status of user '"+userdata.getStatus()+"'." );
				}
				userAdminSession.changeUser(admin,userdata, clearpwd, fromwebservice);
			} else {
				if (log.isDebugEnabled()) {
					log.debug("New User " + username + ", adding userdata. New status of user '"+userdata.getStatus()+"'." );
				}
				// addUserfromWS also checks useUserStorage internally, so don't dupliace the check
				userAdminSession.addUserFromWS(admin,userdata,clearpwd);
			}
		} catch (WaitingForApprovalException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			String msg = "Single transaction enrollment request rejected since approvals are enabled for this CA ("+caid+") or Certificate Profile ("+userdata.getCertificateProfileId()+").";
			log.info(msg);
			throw new ApprovalException(msg);
		}
	}

	/**
	 * Process a request in the CA module.
	 * 
	 * @param admin is the requesting administrator
	 * @param msg is the request message processed by the CA
	 * @param hardTokenSN is the hard token to associate this or null
	 * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType 
	 */
	private byte[] getCertResponseFromPublicKey(Admin admin, IRequestMessage msg, String hardTokenSN, int responseType, UserDataVO userData)
	throws EjbcaException, CertificateEncodingException, CertificateException, IOException {
		byte[] retval = null;
		Class respClass = org.ejbca.core.protocol.X509ResponseMessage.class; 
		IResponseMessage resp =  signSession.createCertificate(admin, msg, respClass, userData);
		java.security.cert.Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
		if(responseType == SecConst.CERT_RES_TYPE_CERTIFICATE){
			retval = cert.getEncoded();
		}
		if(responseType == SecConst.CERT_RES_TYPE_PKCS7){
			retval = signSession.createPKCS7(admin, cert, false);
		}
		if(responseType == SecConst.CERT_RES_TYPE_PKCS7WITHCHAIN){
			retval = signSession.createPKCS7(admin, cert, true);
		}

		if(hardTokenSN != null){ 
			hardTokenSession.addHardTokenCertificateMapping(admin,hardTokenSN,cert);				  
		}
		return retval;
	}

	/**
	 * Edits or adds a user and generates a keystore for that user in a single transaction.
     * Used from EjbcaWS.
     * 
	 * @param admin is the requesting administrator
	 * @param userdata contains information about the user that is about to get a keystore
	 * @param hardTokenSN is the hard token to associate this or null
     * @param keyspec name of ECDSA key or length of RSA and DSA keys  
     * @param keyalg AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_DSA or AlgorithmConstants.KEYALGORITHM_ECDSA
     * @param createJKS true to create a JKS, false to create a PKCS12
     * @return an encoded keystore of the type specified in responseType 
     */
	public byte[] processSoftTokenReq(Admin admin, UserDataVO userdata, String hardTokenSN, String keyspec, String keyalg, boolean createJKS)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException,
	SignatureException, IOException, ObjectNotFoundException, CreateException, CertificateException,UserDoesntFullfillEndEntityProfile,
	ApprovalException, EjbcaException, KeyStoreException, NoSuchAlgorithmException,
	InvalidAlgorithmParameterException, PersistenceException {
		
		// This is the secret sauce, do the end entity handling automagically here before we get the cert
		addOrEditUser(admin, userdata, true, true);
		// Process request
		byte[] ret = null;
		try {
			// Get key recovery info
			boolean usekeyrecovery = raAdminSession.getCachedGlobalConfiguration(admin).getEnableKeyRecovery();
			if (log.isDebugEnabled()) {
				log.debug("usekeyrecovery: "+usekeyrecovery);
			}
			boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery &&  (userdata.getStatus() != UserDataConstants.STATUS_KEYRECOVERY);
			if (log.isDebugEnabled()) {
				log.debug("userdata.getKeyRecoverable(): "+userdata.getKeyRecoverable());
				log.debug("userdata.getStatus(): "+userdata.getStatus());
				log.debug("savekeys: "+savekeys);
			}
			boolean loadkeys = (userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			if (log.isDebugEnabled()) {
				log.debug("loadkeys: "+loadkeys);
			}
			int endEntityProfileId = userdata.getEndEntityProfileId();
			EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(admin, endEntityProfileId);
			boolean reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
			if (log.isDebugEnabled()) {
				log.debug("reusecertificate: "+reusecertificate);
			}
			// Generate keystore
			String password = userdata.getPassword();
			String username = userdata.getUsername();
			int caid = userdata.getCAId();
		    GenerateToken tgen = new GenerateToken(authenticationSession, userAdminSession, caAdminSession, keyRecoverySession, signSession);
		    KeyStore keyStore = tgen.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, createJKS, loadkeys, savekeys, reusecertificate, endEntityProfileId);
			String alias = keyStore.aliases().nextElement();
		    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
		    if ( (hardTokenSN != null) && (cert != null) ) {
		    	hardTokenSession.addHardTokenCertificateMapping(admin,hardTokenSN,cert);                 
		    }
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			keyStore.store(baos, password.toCharArray());
			ret = baos.toByteArray();
		} catch (NotFoundException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeyException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchAlgorithmException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidKeySpecException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (NoSuchProviderException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (SignatureException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (IOException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (CertificateException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (EjbcaException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (InvalidAlgorithmParameterException e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw e;
		} catch (RuntimeException e) {
			throw e;
		} catch (Exception e) {
			sessionContext.setRollbackOnly();	// This is an application exception so it wont trigger a roll-back automatically
			throw new KeyStoreException(e);
		}
	    return ret;
	}
}
