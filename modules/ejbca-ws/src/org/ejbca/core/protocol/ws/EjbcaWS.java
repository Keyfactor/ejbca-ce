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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
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
import javax.ejb.DuplicateKeyException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;
import javax.jws.WebService;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.ws.WebServiceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.netscape.NetscapeCertRequest;
import org.ejbca.config.WebServiceConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.CreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovedActionAdmin;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.core.model.util.EjbRemoteHelper;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.core.protocol.CVCRequestMessage;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.SimpleRequestMessage;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.logger.TransactionLogger;
import org.ejbca.core.protocol.ws.logger.TransactionTags;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.PinDataWS;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.AlgorithmUtil;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.RequestMessageUtils;
import org.ejbca.util.keystore.KeyTools;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

import com.novosec.pkix.asn1.crmf.CertRequest;

/**
 * Implementor of the IEjbcaWS interface.
 * Keep this class free of other helper methods, and implement them in the helper classes instead.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
@WebService
public class EjbcaWS implements IEjbcaWS {
	@Resource
	private WebServiceContext wsContext;	
	
	// TODO: Is more than one instance created of this class? If so, we should probably cache the helper..
	private EjbRemoteHelper ejb = new EjbRemoteHelper();
	private ApprovalSessionRemote approvalSession = ejb.getApprovalSession();
    private AuthenticationSessionRemote authenticationSession = ejb.getAuthenticationSession();
    private AuthorizationSessionRemote authorizationSession = ejb.getAuthorizationSession();
    private CAAdminSessionRemote caAdminSession = ejb.getCAAdminSession();
    private CertificateRequestSessionRemote certificateRequestSession = ejb.getCertficateRequestSession();
    private CertificateStoreSessionRemote certificateStoreSession = ejb.getCertStoreSession();
    private CreateCRLSessionRemote crlSession = ejb.getCrlSession();
    private HardTokenSessionRemote hardTokenSession = ejb.getHardTokenSession();
    private KeyRecoverySessionRemote keyRecoverySession = ejb.getKeyRecoverySession();
    private LogSessionRemote logSession = ejb.getLogSession();
    private PublisherQueueSessionRemote publisherQueueSession = ejb.getPublisherQueueSession();
    private PublisherSessionRemote publisherSession = ejb.getPublisherSession();
    private RaAdminSessionRemote raAdminSession = ejb.getRAAdminSession();
    private SignSessionRemote signSession = ejb.getSignSession();
    private UserAdminSessionRemote userAdminSession = ejb.getUserAdminSession();
    private UserDataSourceSessionRemote userDataSourceSession = ejb.getUserDataSourceSession();
	
	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;
	
	private static final int REQTYPE_PKCS10 = 1;
	private static final int REQTYPE_CRMF = 2;
	private static final int REQTYPE_SPKAC = 3;
	private static final int REQTYPE_CVC = 4;
	
	private static final Logger log = Logger.getLogger(EjbcaWS.class);	
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private void logAdminName(Admin admin, IPatternLogger logger) {
        final X509Certificate cert = (X509Certificate)admin.getAdminInformation().getX509Certificate();
        logger.paramPut(TransactionTags.ADMIN_DN.toString(), cert.getSubjectDN().toString());
        logger.paramPut(TransactionTags.ADMIN_ISSUER_DN.toString(), cert.getIssuerDN().toString());
    }
    /**
	 * @throws IllegalQueryException 
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#editUser(org.ejbca.core.protocol.ws.objects.UserDataVOWS)
	 */	
	public void editUser(UserDataVOWS userdata)
			throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
        	EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		  Admin admin = ejbhelper.getAdmin();
          logAdminName(admin,logger);
		  UserDataVO userdatavo = ejbhelper.convertUserDataVOWS(admin, userdata);

		  authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +userdatavo.getCAId());
		  
		  if(userAdminSession.existsUser(admin, userdatavo.getUsername())){
			  log.debug("User " + userdata.getUsername() + " exists, update the userdata. New status of user '"+userdata.getStatus()+"'." );
			  userAdminSession.changeUser(admin,userdatavo,userdata.isClearPwd(), true);
		  }else{
			  log.debug("New User " + userdata.getUsername() + ", adding userdata. New status of user '"+userdata.getStatus()+"'." );
			  userAdminSession.addUserFromWS(admin,userdatavo,userdata.isClearPwd());
		  }
		}catch(UserDoesntFullfillEndEntityProfile e){
			log.debug(e.toString());
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
			throw e;
	    } catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (AuthorizationDeniedException e) {
            final String errorMessage = "AuthorizationDeniedException when editing user "+userdata.getUsername()+": "+e.getMessage();
			log.info(errorMessage);
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorMessage);
			throw e;
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
		} catch (DuplicateKeyException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_ALREADY_EXISTS, Level.INFO);
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} finally {
		    logger.writeln();
            logger.flush();
        }
	}
	
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findUser(org.ejbca.core.protocol.ws.objects.UserMatch)
	 */
	
	public List<UserDataVOWS> findUser(UserMatch usermatch) throws AuthorizationDeniedException, IllegalQueryException, EjbcaException {		
    	ArrayList<UserDataVOWS> retval = null;
        log.debug("Find user with match '"+usermatch.getMatchvalue()+"'.");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		  Admin admin = ejbhelper.getAdmin();
          logAdminName(admin,logger);
          Query query = ejbhelper.convertUserMatch(admin, usermatch);		  		  
		  Collection<UserDataVO> result = userAdminSession.query(admin, query, null,null, MAXNUMBEROFROWS); // also checks authorization
		  
		  if(result.size() > 0){
		    retval = new ArrayList<UserDataVOWS>();
		    Iterator<UserDataVO> iter = result.iterator();
		    for(int i=0; i<result.size();i++){
		    	UserDataVO userdata = iter.next();
		    	retval.add(ejbhelper.convertUserDataVO(admin,userdata));
		    }		    
		  }

		}catch(AuthorizationDeniedException e){
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
			throw e;
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} finally {
            logger.writeln();
            logger.flush();
        }
		return retval;

	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findCerts(java.lang.String, boolean)
	 */
	public List<Certificate> findCerts(String username, boolean onlyValid) throws AuthorizationDeniedException, EjbcaException {
        log.debug("Find certs for user '"+username+"'.");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		List<Certificate> retval = new ArrayList<Certificate>();
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			if (userAdminSession.findUser(admin,username) != null) {  // checks authorization on CA and profiles and view_end_entity
				Collection<java.security.cert.Certificate> certs;
				if (onlyValid) {
					certs = certificateStoreSession.findCertificatesByUsernameAndStatus(admin, username, SecConst.CERT_ACTIVE);
				} else {
					certs = certificateStoreSession.findCertificatesByUsername(admin, username);
				}
				retval = ejbhelper.returnAuthorizedCertificates(admin, certs, onlyValid);
			} else {
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				log.debug(msg);				
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} finally {
            logger.writeln();
            logger.flush();
        }
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getLastCertChain(java.lang.String)
	 */
	public List<Certificate> getLastCertChain(String username) throws AuthorizationDeniedException, EjbcaException {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCertChain: "+username);
		}
		final List<Certificate> retval = new ArrayList<Certificate>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			if (userAdminSession.findUser(admin, username) != null) { // checks authorization on CA and profiles and view_end_entity
				Collection<java.security.cert.Certificate> certs = certificateStoreSession.findCertificatesByUsername(admin,username);
				if (certs.size() > 0) {
					// The latest certificate will be first
					java.security.cert.Certificate lastcert = certs.iterator().next();
					if (lastcert != null) {
						log.debug("Found certificate for user with subjectDN: "+CertTools.getSubjectDN(lastcert)+" and serialNo: "+CertTools.getSerialNumberAsString(lastcert)); 
						retval.add(new Certificate(lastcert));
						// If we added a certificate, we will also append the CA certificate chain
						boolean selfSigned = false;
						int bar = 0; // to control so we don't enter an infinite loop. Max chain length is 10
						while ( (!selfSigned) && (bar < 10) ) {
							bar++;
							String issuerDN = CertTools.getIssuerDN(lastcert); 
							Collection<java.security.cert.Certificate> cacerts = certificateStoreSession.findCertificatesBySubject(admin, issuerDN);
							if ( (cacerts == null) || (cacerts.size() == 0) ) { 						
								log.info("No certificate found for CA with subjectDN: "+issuerDN);
								break;
							}
							Iterator<java.security.cert.Certificate> iter = cacerts.iterator();
							while (iter.hasNext()) {
								java.security.cert.Certificate cert = (java.security.cert.Certificate)iter.next();
								try {
									lastcert.verify(cert.getPublicKey());
									// this was the right certificate
									retval.add(new Certificate(cert));
									// To determine if we have found the last certificate or not
									selfSigned = CertTools.isSelfSigned(cert);
									// Find the next certificate in the chain now
									lastcert = cert;
									break; // Break of iteration over this CAs certs
								} catch (Exception e) {
									log.debug("Failed verification when looking for CA certificate, this was not the correct CA certificate. IssuerDN: "+issuerDN+", serno: "+CertTools.getSerialNumberAsString(cert));
								}
							}							
						}
						
					} else {
						log.debug("Found no certificate (in non null list??) for user "+username);
					}
				} else {
					log.debug("Found no certificate for user "+username);
				}
			} else {
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);
				log.debug(msg);
			}
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateEncodingException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		if (log.isTraceEnabled()) {
			log.trace("<getLastCertChain: "+username);
		}
		return retval;
	}


	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#crmfRequest(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse crmfRequest(String username, String password,
			String crmf, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    crmf, REQTYPE_CRMF, hardTokenSN, responseType, logger));
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#spkacRequest(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse spkacRequest(String username, String password,
			String spkac, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    spkac, REQTYPE_SPKAC, hardTokenSN, responseType, logger));
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/** Method called from cvcRequest that simply verifies a CVCertificate with a public key and throws AuthorizationDeniedException
	 * if verification works. Used to check if a request is sent containing the same public key.
	 * this could be replaced by enforcing unique public key on the CA (from EJBCA 3.10) actually...
	 * 
	 * @param pk
	 * @param innerreq
	 * @param holderref
	 * @throws AuthorizationDeniedException
	 */
	private void checkInnerCollision(PublicKey pk, CVCertificate innerreq, String holderref) throws AuthorizationDeniedException {
		// Check to see that the inner signature does not verify using an old certificate (public key)
		// because that means the same keys were used, and that is not allowed according to the EU policy
		CardVerifiableCertificate innercert = new CardVerifiableCertificate(innerreq);
		try {
			innercert.verify(pk);										
			String msg = intres.getLocalizedMessage("cvc.error.renewsamekeys", holderref);            	
			log.info(msg);
			throw new AuthorizationDeniedException(msg);
		} catch (SignatureException e) {
			// It was good if the verification failed
		} catch (NoSuchProviderException e) {
			String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderref, e.getMessage());            	
			log.warn(msg, e);
			throw new AuthorizationDeniedException(msg);
		} catch (InvalidKeyException e) {
			String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderref, e.getMessage());            	
			log.warn(msg, e);
			throw new AuthorizationDeniedException(msg);
		} catch (NoSuchAlgorithmException e) {
			String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderref, e.getMessage());            	
			log.info(msg, e);
			throw new AuthorizationDeniedException(msg);
		} catch (CertificateException e) {
			String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderref, e.getMessage());            	
			log.warn(msg, e);
			throw new AuthorizationDeniedException(msg);
		}
	}

	/** Method that gets the public key from a CV certificate, possibly enriching it with domain parameters from the CVCA certificate if it is an EC public key.
	 * @param ejbhelper
	 * @param admin
	 * @param cert
	 * @return
	 * @throws CADoesntExistsException
	 * @throws RemoteException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	private PublicKey getCVPublicKey(EjbcaWSHelper ejbhelper, Admin admin, java.security.cert.Certificate cert) throws CADoesntExistsException, RemoteException {
		PublicKey pk = cert.getPublicKey();
		if (pk instanceof PublicKeyEC) {
			// The public key of IS and DV certificate do not have any EC parameters so we have to do some magic to get a complete EC public key
			// First get to the CVCA certificate that has the parameters
			CAInfo info = caAdminSession.getCAInfoOrThrowException(admin, CertTools.getIssuerDN(cert).hashCode());
			Collection<java.security.cert.Certificate> cacerts = info.getCertificateChain();
			if (cacerts != null) {
				log.debug("Found CA certificate chain of length: "+cacerts.size());
				// Get the last cert in the chain, it is the CVCA cert
				Iterator<java.security.cert.Certificate> i = cacerts.iterator();
				java.security.cert.Certificate cvcacert = null;
				while (i.hasNext()) {
					cvcacert = i.next();
				}
				if (cvcacert != null) {
					// Do the magic adding of parameters, if they don't exist in the pk
					try {
						pk = KeyTools.getECPublicKeyWithParams(pk, cvcacert.getPublicKey());
					} catch (InvalidKeySpecException e) {
						String msg = intres.getLocalizedMessage("cvc.error.outersignature", CertTools.getSubjectDN(cert), e.getMessage());            	
						log.warn(msg, e);
					} catch (NoSuchProviderException e) {
						String msg = intres.getLocalizedMessage("cvc.error.outersignature", CertTools.getSubjectDN(cert), e.getMessage());            	
						log.warn(msg, e);
					} catch (NoSuchAlgorithmException e) {
						String msg = intres.getLocalizedMessage("cvc.error.outersignature", CertTools.getSubjectDN(cert), e.getMessage());            	
						log.info(msg, e);
					}
				}
			}											
		}
		return pk;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#cvcRequest
	 */
	public List<Certificate> cvcRequest(String username, String password, String cvcreq)
			throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException,
			EjbcaException, ApprovalException, WaitingForApprovalException, SignRequestException, CertificateExpiredException {
		log.trace(">cvcRequest");
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();

		// If password is empty we can generate a big random one to use instead
		if (StringUtils.isEmpty(password)) {
			AllPrintableCharPasswordGenerator gen = new AllPrintableCharPasswordGenerator();
			password = gen.getNewPassword(15, 20);
			log.debug("Using a long random password");
		}
		// get and old status that we can remember so we can reset status if this fails in the last step
		int olduserStatus = UserDataConstants.STATUS_GENERATED;
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
			 UserDataVO user = userAdminSession.findUser(admin, username);
			// See if this user already exists.
			// We allow renewal of certificates for IS's that are not revoked
			// In that case look for it's last old certificate and try to authenticate the request using an outer signature.
			// If this verification is correct, set status to NEW and continue process the request.
			if (user != null) {
				olduserStatus = user.getStatus();
				// If user is revoked, we can not proceed
				if ( (olduserStatus == UserDataConstants.STATUS_REVOKED) || (olduserStatus == UserDataConstants.STATUS_HISTORICAL) ) {
					throw new AuthorizationDeniedException("User '"+username+"' is revoked.");
				}
				CVCObject parsedObject = CertificateParser.parseCVCObject(Base64.decode(cvcreq.getBytes()));
				if (parsedObject instanceof CVCAuthenticatedRequest) {
					log.debug("Received an authenticated request, could be an initial DV request signed by CVCA or a renewal for DV or IS.");
					CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
					CVCPublicKey cvcKey = authreq.getRequest().getCertificateBody().getPublicKey();
					String algorithm = AlgorithmUtil.getAlgorithmName(cvcKey.getObjectIdentifier());
					log.debug("Received request has a public key with algorithm: "+algorithm);
					HolderReferenceField holderRef = authreq.getRequest().getCertificateBody().getHolderReference();
					CAReferenceField caRef = authreq.getAuthorityReference();

					// Check to see that the inner signature does not also verify using an old certificate
					// because that means the same keys were used, and that is not allowed according to the EU policy
					// This must be done whether it is signed by CVCA or a renewal request
					Collection<java.security.cert.Certificate> oldcerts = certificateStoreSession.findCertificatesByUsername(admin, username);
					if (oldcerts != null) {
						log.debug("Found "+oldcerts.size()+" old certificates for user "+username);
						Iterator<java.security.cert.Certificate> iterator = oldcerts.iterator(); 
						while (iterator.hasNext()) {
							java.security.cert.Certificate cert = iterator.next();
							PublicKey pk = getCVPublicKey(ejbhelper, admin, cert);
							CVCertificate innerreq = authreq.getRequest();
							checkInnerCollision(pk, innerreq, holderRef.getConcatenated()); // Throws AuthorizationDeniedException
						}
					}

					boolean verifiedOuter = false; // So we can throw an error if we could not verify
					if (StringUtils.equals(holderRef.getMnemonic(), caRef.getMnemonic()) && StringUtils.equals(holderRef.getCountry(), caRef.getCountry())) {
						log.debug("Authenticated request is self signed, we will try to verify it using user's old certificate.");
						Collection<java.security.cert.Certificate> certs = certificateStoreSession.findCertificatesByUsername(admin, username);
						// certs contains certificates ordered with last expire date first. Last expire date should be last issued cert
						// We have to iterate over available user certificates, because we don't know which on signed the old one
						// and cv certificates have very coarse grained validity periods so we can't really know which one is the latest one
						// if 2 certificates are issued the same day.
						if (certs != null) {
							log.debug("Found "+certs.size()+" old certificates for user "+username);
							Iterator<java.security.cert.Certificate> iterator = certs.iterator(); 
							while (iterator.hasNext()) {
								java.security.cert.Certificate cert = iterator.next();
								try {
									// Only allow renewal if the old certificate is valid
									PublicKey pk = getCVPublicKey(ejbhelper, admin, cert);
									if (log.isDebugEnabled()) {
										log.debug("Trying to verify the outer signature with an old certificate, fp: "+CertTools.getFingerprintAsString(cert));										
									}
									authreq.verify(pk);
									log.debug("Verified outer signature");
									// Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
									verifiedOuter = true; 
									if (ejbhelper.checkValidityAndSetUserPassword(admin, cert, username, password)) {
										// If we managed to verify the certificate we will break out of the loop									
										break;
									}
									
									// If verification of outer signature fails because the signature is invalid we will break and deny the request...with a message
								} catch (InvalidKeyException e) {
									String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
									log.warn(msg, e);
								} catch (CertificateExpiredException e) { // thrown by checkValidityAndSetUserPassword
									String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
									// Only log this with DEBUG since it will be a common case that happens, nothing that should cause any alerts
									log.debug(msg);
									// This exception we want to throw on, because we want to give this error if there was a certificate suitable for
									// verification, but it had expired. This is thrown by checkValidityAndSetUserPassword after the request has already been 
									// verified using the public key of the certificate.
									throw e;
								} catch (CertificateException e) {
									String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
									log.warn(msg, e);
								} catch (NoSuchAlgorithmException e) {
									String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
									log.info(msg, e);
								} catch (NoSuchProviderException e) {
									String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
									log.warn(msg, e);
								} catch (SignatureException e) {
									// Failing to verify the outer signature will be normal, since we must try all old certificates
									if (log.isDebugEnabled()) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.debug(msg);									
									}
								}
							} // while (iterator.hasNext()) {
							// if verification failed because the old cert was not yet valid, continue processing as usual, using the sent in username/password hoping the
							// status is NEW and password is correct. If old certificate was expired a CertificateExpiredException is thrown above.

						} // if (certs != null) {
						
						// If there are no old certificate, continue processing as usual, using the sent in username/password hoping the
						// status is NEW and password is correct.
					} else { // if (StringUtils.equals(holderRef, caRef))
						// Subject and issuerDN is CN=Mnemonic,C=Country
						String dn = "CN="+caRef.getMnemonic()+",C="+caRef.getCountry();
						log.debug("Authenticated request is not self signed, we will try to verify it using a CVCA certificate: "+dn);
						CAInfo info = caAdminSession.getCAInfoOrThrowException(admin, CertTools.stringToBCDNString(dn).hashCode());
						if (info != null) {
							Collection<java.security.cert.Certificate> certs = info.getCertificateChain();
							if (certs != null) {
								log.debug("Found "+certs.size()+" certificates in chain for CA with DN: "+dn);							
								Iterator<java.security.cert.Certificate> iterator = certs.iterator();
								if (iterator.hasNext()) {
									// The CA certificate is first in chain
									java.security.cert.Certificate cert = iterator.next();
									if (log.isDebugEnabled()) {
										log.debug("Trying to verify the outer signature with a CVCA certificate, fp: "+CertTools.getFingerprintAsString(cert));										
									}
									try {
										// The CVCA certificate always contains the full key parameters, no need to du any EC curve parameter magic here
										authreq.verify(cert.getPublicKey());
										log.debug("Verified outer signature");
										verifiedOuter = true; 
										// Yes we did it, we can move on to the next step because the outer signature was actually created with some old certificate
										if (!ejbhelper.checkValidityAndSetUserPassword(admin, cert, username, password)) {
											// If the CA certificate was not valid, we are not happy									
											String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), "CA certificate not valid for CA: "+info.getCAId());            	
											log.info(msg);
											throw new AuthorizationDeniedException(msg);
										}							
									} catch (InvalidKeyException e) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.warn(msg, e);
									} catch (CertificateException e) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.warn(msg, e);
									} catch (NoSuchAlgorithmException e) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.warn(msg, e);
									} catch (NoSuchProviderException e) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.warn(msg, e);
									} catch (SignatureException e) {
										String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), e.getMessage());            	
										log.warn(msg, e);
									}							
								}								
							} else {
								log.info("No CA certificate found to authenticate request: "+dn);
							}
						} else {
							log.info("No CA found to authenticate request: "+dn);
						}
					}
					// if verification failed because we could not verify the outer signature at all it is an error
					if (!verifiedOuter) {
						String msg = intres.getLocalizedMessage("cvc.error.outersignature", holderRef.getConcatenated(), "No certificate found that could authenticate request");            	
						log.info(msg);
						throw new AuthorizationDeniedException(msg);
					}
				} // if (parsedObject instanceof CVCAuthenticatedRequest)
				// If it is not an authenticated request, with an outer signature, continue processing as usual, 
				// using the sent in username/password hoping the status is NEW and password is correct. 
			} else {
				// If there are no old user, continue processing as usual... it will fail
				log.debug("No existing user with username: "+username);
			}
			
			// Finally generate the certificate (assuming status is NEW and password is correct
			byte[] response = processCertReq(username, password, cvcreq, REQTYPE_CVC, null, CertificateHelper.RESPONSETYPE_CERTIFICATE, logger);
			CertificateResponse ret = new CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE, response);
			byte[] b64cert = ret.getData();
			CVCertificate certObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
			java.security.cert.Certificate iscert = new CardVerifiableCertificate(certObject); 
			ArrayList<Certificate> retval = new ArrayList<Certificate>();
			retval.add(new Certificate((java.security.cert.Certificate)iscert));
			// Get the certificate chain
			if (user != null) {
				int caid = user.getCAId();
				caAdminSession.verifyExistenceOfCA(caid);
				Collection<java.security.cert.Certificate> certs = signSession.getCertificateChain(admin, caid);
				Iterator<java.security.cert.Certificate> iter = certs.iterator();
				while (iter.hasNext()) {
					java.security.cert.Certificate cert = iter.next();
					retval.add(new Certificate(cert));
				}
			}
			log.trace("<cvcRequest");
			return retval;
		} catch (EjbcaException e) {
			// Have this first, if processReq throws an EjbcaException we want to reset status
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw e;
		} catch (RemoteException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ServiceLocatorException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CreateException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ParseException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ConstructionException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (NoSuchFieldException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateEncodingException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	} // cvcRequest

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest
	 */
	public byte[] caRenewCertRequest(String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		if (log.isTraceEnabled()) {
			log.trace(">caRenewCertRequest");			
		}
		log.debug("Create certificate request for CA "+caname+", regeneratekeys="+regenerateKeys+", usenextkey="+usenextkey+", activatekey="+activatekey+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
		byte[] ret = null;
		try {
			ret = ejbhelper.caRenewCertRequest(ejbhelper, admin, caname, cachain, regenerateKeys, usenextkey, activatekey, keystorepwd);
		} catch (CertPathValidatorException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CATokenOfflineException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CATokenAuthenticationFailedException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
		}
		if (log.isTraceEnabled()) {
			log.trace("<caRenewCertRequest");
		}
		return ret;
	} // caRenewCertRequest

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caCertResponse
	 */
	public void caCertResponse(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		log.trace(">caCertResponse");
		log.info("Import certificate response for CA "+caname+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
		try {
			ejbhelper.caCertResponse(ejbhelper, admin, caname, cert, cachain, keystorepwd);			
		} catch (CertPathValidatorException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CATokenOfflineException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CATokenAuthenticationFailedException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
		}
		log.trace("<caCertResponse");
	} // caCertResponse

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs10Request(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse pkcs10Request(String username, String password, String pkcs10, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
	EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("PKCS10 from user '"+username+"'.");
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    pkcs10, REQTYPE_PKCS10, hardTokenSN, responseType, logger));
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
	
	private byte[] processCertReq(String username, String password, String req, int reqType,
			String hardTokenSN, String responseType, IPatternLogger logger) throws EjbcaException, AuthorizationDeniedException {
		byte[] retval = null;

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin();			  
            logAdminName(admin,logger);

			// check authorization to CAID
			UserDataVO userdata = userAdminSession.findUser(admin,username);
			if(userdata == null){
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				throw new NotFoundException(msg);
			}
			int caid = userdata.getCAId();
			caAdminSession.verifyExistenceOfCA(caid);
			authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
			authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_CREATECERTIFICATE);

			// Check tokentype
			if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
				throw EjbcaWSHelper.getEjbcaException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests",
                                        logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
			}

			IRequestMessage imsg = null;
			if (reqType == REQTYPE_PKCS10) {				
				IRequestMessage pkcs10req=RequestMessageUtils.genPKCS10RequestMessage(req.getBytes());
				PublicKey pubKey = pkcs10req.getRequestPublicKey();
				imsg = new SimpleRequestMessage(pubKey, username, password);
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
						log.debug("SPKAC POPO verification Failed");
						throw new SignRequestSignatureException("Invalid signature in NetscapeCertRequest, popo-verification failed.");
					}
					log.debug("POPO verification successful");
					PublicKey pubKey = nscr.getPublicKey();
					imsg = new SimpleRequestMessage(pubKey, username, password);
				}		
			}
			if (reqType == REQTYPE_CRMF) {
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
				CVCRequestMessage reqmsg = new CVCRequestMessage(cvccert.getDEREncoded());
				reqmsg.setUsername(username);
				reqmsg.setPassword(password);
				// Popo is really actually verified by the CA (in RSASignSessionBean) as well
				if (reqmsg.verify() == false) {
					log.debug("CVC POPO verification Failed");
					throw new SignRequestSignatureException("Invalid inner signature in CVCRequest, popo-verification failed.");
				} else {
					log.debug("POPO verification successful");					
				}
				imsg = reqmsg;
			}
			if (imsg != null) {
				retval = getCertResponseFromPublicKey(admin, imsg, hardTokenSN, responseType, ejbhelper);
			}
		}catch(AuthorizationDeniedException ade){
			throw ade;
		} catch (InvalidKeyException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY, Level.ERROR);
		} catch (IllegalKeyException e) {
			// Don't log a bad error for this (user's key length too small)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.ILLEGAL_KEY, Level.DEBUG);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
		} catch (SignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.SIGNATURE_ERROR, Level.ERROR);
		} catch (SignRequestSignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, null, Level.ERROR);
		} catch (InvalidKeySpecException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY_SPEC, Level.ERROR);
		} catch (NoSuchAlgorithmException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (NoSuchProviderException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (IOException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ParseException e) {
			// CVC error
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ConstructionException e) {
			// CVC error
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (NoSuchFieldException e) {
			// CVC error
            throw EjbcaWSHelper.getInternalException(e, logger);
		}

		return retval;
	}


	private byte[] getCertResponseFromPublicKey(Admin admin, IRequestMessage msg,
			String hardTokenSN, String responseType, EjbcaWSHelper ejbhelper) throws EjbcaException, CertificateEncodingException, CertificateException, IOException {
		byte[] retval = null;
		IResponseMessage resp =  signSession.createCertificate(admin, msg, org.ejbca.core.protocol.X509ResponseMessage.class);
		java.security.cert.Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)){
			retval = cert.getEncoded();
		}
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)){
			retval = signSession.createPKCS7(admin, cert, false);
		}
		if(responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)){
			retval = signSession.createPKCS7(admin, cert, true);
		}


		if(hardTokenSN != null){ 
			hardTokenSession.addHardTokenCertificateMapping(admin,hardTokenSN,cert);				  
		}
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs12Req(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public KeyStore pkcs12Req(String username, String password, String hardTokenSN, String keyspec, String keyalg)
		throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException {
		
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			  EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			  Admin admin = ejbhelper.getAdmin();
              logAdminName(admin,logger);

			  // check CAID
			  UserDataVO userdata = userAdminSession.findUser(admin,username);
			  if(userdata == null){
				  String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				  throw new NotFoundException(msg);
			  }
			  int caid = userdata.getCAId();
			  caAdminSession.verifyExistenceOfCA(caid);
			  authorizationSession.isAuthorized(admin,AccessRulesConstants.CAPREFIX +caid);

			  authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_CREATECERTIFICATE);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_P12){
                  throw EjbcaWSHelper.getEjbcaException("Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests", logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
			  }

			  boolean usekeyrecovery = raAdminSession.getCachedGlobalConfiguration(admin).getEnableKeyRecovery();
			  log.debug("usekeyrecovery: "+usekeyrecovery);
			  boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery &&  (userdata.getStatus() != UserDataConstants.STATUS_KEYRECOVERY);
			  log.debug("userdata.getKeyRecoverable(): "+userdata.getKeyRecoverable());
			  log.debug("userdata.getStatus(): "+userdata.getStatus());
			  log.debug("savekeys: "+savekeys);
			  boolean loadkeys = (userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			  log.debug("loadkeys: "+loadkeys);
			  int endEntityProfileId = userdata.getEndEntityProfileId();
			  EndEntityProfile endEntityProfile = raAdminSession.getEndEntityProfile(admin, endEntityProfileId);
			  boolean reusecertificate = endEntityProfile.getReUseKeyRevoceredCertificate();
			  log.debug("reusecertificate: "+reusecertificate);

			  try {
				  GenerateToken tgen = new GenerateToken(authenticationSession, caAdminSession, keyRecoverySession, signSession);
				  java.security.KeyStore pkcs12 = tgen.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
                  final KeyStore retval = new KeyStore(pkcs12, password);
				  final Enumeration<String> en = pkcs12.aliases();
				  final String alias = en.nextElement();
                  final X509Certificate cert = (X509Certificate) pkcs12.getCertificate(alias);
                  if ( (hardTokenSN != null) && (cert != null) ) {
                      hardTokenSession.addHardTokenCertificateMapping(admin,hardTokenSN,cert);                 
                  }
                  return retval;
              } catch (AuthLoginException e) {
                  throw e;
              } catch (AuthStatusException e) {
                  throw e;
              } catch (Exception e) {
                  throw EjbcaWSHelper.getInternalException(e, logger);
			  }
			  
			  
			}catch(AuthorizationDeniedException ade){
				throw ade;
			} catch (ClassCastException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);
			} catch (EJBException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);
			} catch (AuthStatusException e) {
				// Don't log a bad error for this (user wrong status)
                throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
			} catch (AuthLoginException e) {
                throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
			} catch (IllegalKeyException e) {
				// Don't log a bad error for this (user's key length too small)
                throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.ILLEGAL_KEY, Level.DEBUG);
			/*} catch (RemoteException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);*/
            } catch( RuntimeException t ) {
                logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
                throw t;
            } finally {
                logger.writeln();
                logger.flush();
			}
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeCert(java.lang.String, java.lang.String, int)
	 */
	
	public void revokeCert(String issuerDN, String certificateSN, int reason) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        log.debug("Revoke cert with serial number '"+certificateSN+"' from issuer '"+issuerDN+"' with reason '"+reason+"'.");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

			int caid = CertTools.stringToBCDNString(issuerDN).hashCode();
			caAdminSession.verifyExistenceOfCA(caid);

			BigInteger serno = new BigInteger(certificateSN,16);
			String username = certificateStoreSession.findUsernameByCertSerno(admin,serno,issuerDN);

			// check that admin is authorized to CA
			authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);			  

			// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
			// that was permanently revoked
			userAdminSession.revokeCert(admin,serno, issuerDN, username,  reason);
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (AlreadyRevokedException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, ErrorCode.CERT_WRONG_STATUS, null);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeUser(java.lang.String, int, boolean)
	 */
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

			// check username
			UserDataVO userdata = userAdminSession.findUser(admin,username);
			if(userdata == null){
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				throw new NotFoundException(msg);
			}
			// Check caid
			int caid = userdata.getCAId();
			caAdminSession.verifyExistenceOfCA(caid);
			authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);						
			if (deleteUser) {
				userAdminSession.revokeAndDeleteUser(admin,username,reason);
			} else {
				userAdminSession.revokeUser(admin,username,reason);
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		}  catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (RemoveException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#keyRecoverNewest(java.lang.String)
	 */
	public void keyRecoverNewest(String username) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException {
		log.trace(">keyRecoverNewest");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

            boolean usekeyrecovery = raAdminSession.getCachedGlobalConfiguration(admin).getEnableKeyRecovery();  
            if(!usekeyrecovery){
				throw EjbcaWSHelper.getEjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.",
                                        logger, ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, null);
            }   
			UserDataVO userdata = userAdminSession.findUser(admin, username);
			if(userdata == null){
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				throw new NotFoundException(msg);
			}
			if(keyRecoverySession.isUserMarked(admin, username)){
				// User is already marked for recovery.
				return;                     
			}
			// check CAID
			int caid = userdata.getCAId();
			caAdminSession.verifyExistenceOfCA(caid);
			authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);						

			// Do the work, mark user for key recovery
			userAdminSession.prepareForKeyRecovery(admin, userdata.getUsername(), userdata.getEndEntityProfileId(), null);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		log.trace("<keyRecoverNewest");
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeToken(java.lang.String, int)
	 */
	public void revokeToken(String hardTokenSN, int reason)
	throws CADoesntExistsException, RemoteException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            revokeToken(ejbhelper.getAdmin(), hardTokenSN, reason, logger);
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
	
	private void revokeToken(Admin admin, String hardTokenSN, int reason, IPatternLogger logger) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, AlreadyRevokedException, ApprovalException, WaitingForApprovalException {
		ApprovalException lastApprovalException = null;
		WaitingForApprovalException lastWaitingForApprovalException = null;
		AuthorizationDeniedException lastAuthorizationDeniedException = null;
		AlreadyRevokedException lastAlreadyRevokedException = null;
		boolean success = false;
		try{
            logAdminName(admin,logger);
			Collection<X509Certificate> certs = hardTokenSession.findCertificatesInHardToken(admin,hardTokenSN);
			Iterator<X509Certificate> iter = certs.iterator();
			String username = null;
			while(iter.hasNext()){
				X509Certificate next = iter.next();
				if(username == null){
					username = certificateStoreSession.findUsernameByCertSerno(admin,CertTools.getSerialNumber(next),CertTools.getIssuerDN(next));
				}
				
				// check that admin is authorized to CA
				int caid = CertTools.getIssuerDN(next).hashCode();
				caAdminSession.verifyExistenceOfCA(caid);
				authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
				try {
					// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
					// that was permanently revoked
					userAdminSession.revokeCert(admin,CertTools.getSerialNumber(next),CertTools.getIssuerDN(next),username,reason);
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
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (AlreadyRevokedException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, ErrorCode.CERT_WRONG_STATUS, null);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} 
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#checkRevokationStatus(java.lang.String, java.lang.String)
	 */
	
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		  Admin admin = ejbhelper.getAdmin();		  
          logAdminName(admin,logger);

		  // check that admin is autorized to CA
		  int caid = CertTools.stringToBCDNString(issuerDN).hashCode();
		  caAdminSession.verifyExistenceOfCA(caid);
		  authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
		  
		  CertificateStatus certinfo = certificateStoreSession.getStatus(issuerDN, new BigInteger(certificateSN,16));
		  if(certinfo != null){
		    return new RevokeStatus(certinfo, issuerDN, certificateSN);
		  }
		  return null;
		}catch(AuthorizationDeniedException ade){
			throw ade;
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( DatatypeConfigurationException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}	

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isAuthorized(java.lang.String)
	 */
	public boolean isAuthorized(String resource) throws EjbcaException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
            final Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			return authorizationSession.isAuthorized(admin, resource);	
		}catch(AuthorizationDeniedException ade){
            return false;
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#fetchUserData(java.util.List, java.lang.String)
	 */
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws UserDataSourceException, EjbcaException, AuthorizationDeniedException{
	    
		final Admin admin;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);

		if(WebServiceConfiguration.getNoAuthorizationOnFetchUserData()){
			final Admin tmp = ejbhelper.getAdmin(true);
			admin = new ApprovedActionAdmin(tmp.getAdminInformation().getX509Certificate(), tmp.getUsername(), tmp.getEmail());
		}else{
			admin = ejbhelper.getAdmin();
		}
		
		final ArrayList<UserDataSourceVOWS> retval = new ArrayList<UserDataSourceVOWS>();
		
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
			final ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();
			{
			    final Iterator<String> iter = userDataSourceNames.iterator();
			    while(iter.hasNext()){
			        final String name = iter.next();
			        final int id = userDataSourceSession.getUserDataSourceId(admin, name);
				    if(id != 0){
			            userDataSourceIds.add(new Integer(id));
			        }else{
			            log.error("Error User Data Source with name : " + name + " doesn't exist.");
			        }
			    }
			}
			{
			    final Iterator<UserDataSourceVO> iter = userDataSourceSession.fetch(admin, userDataSourceIds, searchString).iterator();
			    while(iter.hasNext()){
			        UserDataSourceVO next = iter.next();
			        retval.add(new UserDataSourceVOWS(ejbhelper.convertUserDataVO(admin, next.getUserDataVO()),next.getIsFieldModifyableSet()));
			    }
			}
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
        return retval;
	}		
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#genTokenCertificates(org.ejbca.core.protocol.ws.objects.UserDataVOWS, java.util.List, org.ejbca.core.protocol.ws.objects.HardTokenDataWS)
	 */
	public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userDataWS, List<TokenCertificateRequestWS> tokenRequests, HardTokenDataWS hardTokenDataWS, boolean overwriteExistingSN, boolean revocePreviousCards)
		throws CADoesntExistsException, AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException,UserDoesntFullfillEndEntityProfile, ApprovalException, EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException {
		final ArrayList<TokenCertificateResponseWS> retval = new ArrayList<TokenCertificateResponseWS>();

		final Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin(true);
		int endEntityProfileId = 0;
		boolean hardTokenExists = false;
		boolean userExists = false;
		
		ApprovalRequest ar = null;
		boolean approvalSuccessfullStep1 = false;
		boolean isRejectedStep1 = false;

		// Get Significant user Id
		final CAInfo significantcAInfo;
		final ArrayList<java.security.cert.Certificate> genCertificates = new ArrayList<java.security.cert.Certificate>();
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			significantcAInfo = caAdminSession.getCAInfoOrThrowException(intAdmin, userDataWS.getCaName());
		if(significantcAInfo == null){
			throw EjbcaWSHelper.getEjbcaException("Error the given CA : " + userDataWS.getCaName() + " couldn't be found.",
					logger, ErrorCode.CA_NOT_EXISTS, null);
		}
		
			UserDataVO userDataVO = userAdminSession.findUser(intAdmin, userDataWS.getUsername());
			if(userDataVO != null){
				endEntityProfileId = userDataVO.getEndEntityProfileId();
				userExists = true;
			}else{
				endEntityProfileId = raAdminSession.getEndEntityProfileId(intAdmin, userDataWS.getEndEntityProfileName());	    	  
				if(endEntityProfileId == 0){
					throw EjbcaWSHelper.getEjbcaException("Error given end entity profile : " + userDataWS.getEndEntityProfileName() +" couldn't be found",
						logger, ErrorCode.EE_PROFILE_NOT_EXISTS, null);
				}
			}
			
			
			if(ejbhelper.isAdmin()){			
				authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE);
				authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS);
				authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + significantcAInfo.getCAId());
				if(userExists){
					authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_EDITENDENTITY);					
					endEntityProfileId = userDataVO.getEndEntityProfileId();
					authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.EDIT_RIGHTS);
					if(overwriteExistingSN){
						authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_REVOKEENDENTITY);
						authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.REVOKE_RIGHTS);
					}
				}else{
					authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_CREATEENDENTITY);
					authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.CREATE_RIGHTS);
					if(overwriteExistingSN){
						authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_REVOKEENDENTITY);
						authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.REVOKE_RIGHTS);				       
					}
				}

			}else{
				if(WebServiceConfiguration.getApprovalForGenTokenCertificates()){
					ar = new GenerateTokenApprovalRequest(userDataWS.getUsername(), userDataWS.getSubjectDN(), hardTokenDataWS.getLabel(),admin,null,WebServiceConfiguration.getNumberOfRequiredApprovals(),significantcAInfo.getCAId(),endEntityProfileId);
					int status = ApprovalDataVO.STATUS_REJECTED; 					
					try{
					  status = approvalSession.isApproved(admin, ar.generateApprovalId(), 1);
					  approvalSuccessfullStep1 =  status == ApprovalDataVO.STATUS_APPROVED;
					  if(approvalSuccessfullStep1){
						  ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(intAdmin, ar.generateApprovalId());
						  String originalDN = ((GenerateTokenApprovalRequest) approvalDataVO.getApprovalRequest()).getDN();
						  userDataWS.setSubjectDN(originalDN); // replace requested DN with original DN to make sure nothing have changed.
					  }
					  isRejectedStep1 = status == ApprovalDataVO.STATUS_REJECTED;
					  if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
					     || status == ApprovalDataVO.STATUS_EXPIRED){
						  throw new ApprovalException("");
					  }
					}catch(ApprovalException e){
						approvalSession.addApprovalRequest(admin, ar, raAdminSession.getCachedGlobalConfiguration(admin));
						throw new WaitingForApprovalException("Approval request with id " + ar.generateApprovalId() + " have been added for approval.",ar.generateApprovalId());
					}
				}else{
					throw new AuthorizationDeniedException();
				}
			}

		if(ar != null && isRejectedStep1){
			throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " have been rejected.");
		}
		
		if(ar != null && !approvalSuccessfullStep1){
			throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
		}
		
		if(ar != null){
			admin = new ApprovedActionAdmin(admin.getAdminInformation().getX509Certificate(), admin.getUsername(), admin.getEmail());
		}
		
			hardTokenExists = hardTokenSession.existsHardToken(admin, hardTokenDataWS.getHardTokenSN());
			if(hardTokenExists){
				if(overwriteExistingSN){
					// fetch all old certificates and revoke them.
					Collection<java.security.cert.X509Certificate> currentCertificates = hardTokenSession.findCertificatesInHardToken(admin, hardTokenDataWS.getHardTokenSN());
					HardTokenData currentHardToken = hardTokenSession.getHardToken(admin, hardTokenDataWS.getHardTokenSN(), false);
					Iterator<java.security.cert.X509Certificate> iter = currentCertificates.iterator();
					while(iter.hasNext()){
						java.security.cert.X509Certificate nextCert = iter.next();
						try {
							userAdminSession.revokeCert(admin, CertTools.getSerialNumber(nextCert), CertTools.getIssuerDN(nextCert), currentHardToken.getUsername(), RevokedCertInfo.REVOKATION_REASON_SUPERSEDED);
						} catch (AlreadyRevokedException e) {
							// Ignore previously revoked certificates
						} catch (FinderException e) {
                            throw EjbcaWSHelper.getEjbcaException("Error revoking old certificate, the user : " + currentHardToken.getUsername() + " of the old certificate couldn't be found in database.",
                                                    logger, ErrorCode.USER_NOT_FOUND, null);
						} 
					}

				}else{
					throw new HardTokenExistsException("Error hard token with sn " + hardTokenDataWS.getHardTokenSN() + " already exists.");
				}

			}


			if(revocePreviousCards){
				List<HardTokenDataWS> htd = getHardTokenDatas(admin,userDataWS.getUsername(), false, true, logger);
				Iterator<HardTokenDataWS> htdIter = htd.iterator();

				while(htdIter.hasNext()) {
					HardTokenDataWS toRevoke = htdIter.next();
					try{
						  if(hardTokenDataWS.getLabel().equals(HardTokenConstants.LABEL_TEMPORARYCARD) && toRevoke.getLabel() != null && !toRevoke.getLabel().equals(HardTokenConstants.LABEL_TEMPORARYCARD)){

								// Token have extended key usage MS Logon, don't revoke it
								Iterator<X509Certificate> revokeCerts = hardTokenSession.findCertificatesInHardToken(admin, toRevoke.getHardTokenSN()).iterator();

								while(revokeCerts.hasNext()){
									X509Certificate next = revokeCerts.next();							 
									try{
										if(WebServiceConfiguration.getSuspendAllCertificates() || next.getExtendedKeyUsage() == null || !next.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_smartcardlogon.getId())){
											userAdminSession.revokeCert(admin,next.getSerialNumber(), CertTools.getIssuerDN(next), userDataWS.getUsername(),  RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
										}
									}catch(CertificateParsingException e){
										log.error(e);
									} catch (FinderException e) {
										log.error(e);
									}	
								}
						

						}else{
							revokeToken(admin, toRevoke.getHardTokenSN(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, logger);
						}
					}catch(AlreadyRevokedException e){
						// Do nothing
					}
				}
			}
		
		try{
			// Check if the userdata exist and edit/add it depending on which
			String password = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(8, 8);
			UserDataVO userData = ejbhelper.convertUserDataVOWS(admin, userDataWS);
			userData.setPassword(password);
			if(userExists){
				userAdminSession.changeUser(admin, userData, true);
			}else{
				userAdminSession.addUser(admin, userData, true);
			}

			Date bDate = new Date(System.currentTimeMillis() - (10 * 60 * 1000));
			
			Iterator<TokenCertificateRequestWS> iter = tokenRequests.iterator();
			while(iter.hasNext()){
				TokenCertificateRequestWS next = iter.next();

				int certificateProfileId = certificateStoreSession.getCertificateProfileId(admin, next.getCertificateProfileName());
				if(certificateProfileId == 0){
                    EjbcaWSHelper.getEjbcaException("Error the given Certificate Profile : " + next.getCertificateProfileName() + " couldn't be found.",
                                      logger, ErrorCode.CERT_PROFILE_NOT_EXISTS, null);
				}
				
				Date eDate = null;
				
				if(next.getValidityIdDays() != null ){
					try{
						long validity = Long.parseLong(next.getValidityIdDays());
						eDate = new Date(System.currentTimeMillis() + (validity  * 3600 *24 * 1000));
					}catch (NumberFormatException e){
                        EjbcaWSHelper.getEjbcaException("Error : Validity in Days must be a number",
                                          logger, ErrorCode.BAD_VALIDITY_FORMAT, null);
					}
				}
				
				CAInfo cAInfo = caAdminSession.getCAInfo(admin, next.getCAName());
				if(cAInfo == null){
					throw EjbcaWSHelper.getEjbcaException("Error the given CA : " + next.getCAName() + " couldn't be found.",
						logger, ErrorCode.CA_NOT_EXISTS, null);
				}

				authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + cAInfo.getCAId());
				if(next.getType() == HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST){						
					userData.setCertificateProfileId(certificateProfileId);
					userData.setCAId(cAInfo.getCAId());
					userData.setPassword(password);
					userData.setStatus(UserDataConstants.STATUS_NEW);
					userAdminSession.changeUser(admin, userData, false);
					PKCS10RequestMessage pkcs10req = new PKCS10RequestMessage(next.getPkcs10Data());
					java.security.cert.Certificate cert;
					if(eDate == null){
					    cert =  signSession.createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey());
					}else{
						cert =  signSession.createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey(), -1, bDate, eDate);
					}
					
					genCertificates.add(cert);
					retval.add(new TokenCertificateResponseWS(new Certificate(cert)));
				}else
					if(next.getType() == HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST){

						if(!next.getTokenType().equals(HardTokenConstants.TOKENTYPE_PKCS12)){
							throw EjbcaWSHelper.getEjbcaException("Unsupported Key Store Type : " + next.getTokenType() + " only " + HardTokenConstants.TOKENTYPE_PKCS12 + " is supported",
                                                        logger, ErrorCode.NOT_SUPPORTED_KEY_STORE, null);
						}
						KeyPair keys = KeyTools.genKeys(next.getKeyspec(), next.getKeyalg());							  
						userData.setCertificateProfileId(certificateProfileId);
						userData.setCAId(cAInfo.getCAId());
						userData.setPassword(password);
						userData.setStatus(UserDataConstants.STATUS_NEW);
						userAdminSession.changeUser(admin, userData, true);
						X509Certificate cert;
						if(eDate == null){
						    cert =  (X509Certificate) signSession.createCertificate(admin,userData.getUsername(),password, keys.getPublic());
						}else{
							cert =  (X509Certificate) signSession.createCertificate(admin,userData.getUsername(),password, keys.getPublic(), -1, bDate, eDate);
						}
						
						genCertificates.add(cert);      
						// Generate Keystore
						// Fetch CA Cert Chain.	        
						Collection<java.security.cert.Certificate> chain =  caAdminSession.getCAInfo(admin, cAInfo.getCAId()).getCertificateChain();
						String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
						if (alias == null){
							alias = userData.getUsername();
						}	      	      
						java.security.KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

						retval.add(new TokenCertificateResponseWS(new KeyStore(pkcs12, userDataWS.getPassword())));
					}else{
						throw EjbcaWSHelper.getEjbcaException("Error in request, only REQUESTTYPE_PKCS10_REQUEST and REQUESTTYPE_KEYSTORE_REQUEST are supported token requests.",
							logger, ErrorCode.NOT_SUPPORTED_REQUEST_TYPE, null);
					}
			}

		} catch(Exception e){
            throw EjbcaWSHelper.getInternalException(e, logger);
		} finally{
			userAdminSession.setUserStatus(admin, userDataWS.getUsername(), UserDataConstants.STATUS_GENERATED);
		}

		// Add hard token data
		HardToken hardToken;
		String signatureInitialPIN = "";
		String signaturePUK = "";
		String basicInitialPIN = "";
		String basicPUK = "";
		Iterator<PinDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
		while(iter.hasNext()){
			PinDataWS pinData = iter.next();
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
				throw EjbcaWSHelper.getEjbcaException("Unsupported PIN Type " + pinData.getType(),
					logger, ErrorCode.NOT_SUPPORTED_PIN_TYPE, null);
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
			throw EjbcaWSHelper.getEjbcaException("Unsupported Token Type : " + hardTokenDataWS.getTokenType(),
				logger, ErrorCode.NOT_SUPPORTED_TOKEN_TYPE, null);

		}

		hardToken.setLabel(hardTokenDataWS.getLabel());
			if(overwriteExistingSN){
				if(hardTokenExists){
					try {
						hardTokenSession.removeHardToken(admin, hardTokenDataWS.getHardTokenSN());
					} catch (HardTokenDoesntExistsException e) {
						throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.HARD_TOKEN_NOT_EXISTS, Level.ERROR);
					}
				}
			}
			hardTokenSession.addHardToken(admin, hardTokenDataWS.getHardTokenSN(), userDataWS.getUsername(), significantcAInfo.getSubjectDN(), tokenType, hardToken, genCertificates, hardTokenDataWS.getCopyOfSN());

			if(ar!= null){
				approvalSession.markAsStepDone(admin, ar.generateApprovalId(), GenerateTokenApprovalRequest.STEP_1_GENERATETOKEN);
			}
        } catch( EjbcaException e) {
            throw e;
 		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch (FinderException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return retval; 	
	}
	



	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#existsHardToken(java.lang.String)
	 */
	public boolean existsHardToken(String hardTokenSN) throws EjbcaException{
		final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			return hardTokenSession.existsHardToken(admin, hardTokenSN);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenData(java.lang.String)
	 */
	public HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
		throws CADoesntExistsException, AuthorizationDeniedException, HardTokenDoesntExistsException, NotFoundException, ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException, EjbcaException {
		HardTokenDataWS retval = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin(true);
		ApprovalRequest ar = null;
		boolean isApprovedStep0 = false;
		boolean isRejectedStep0 = false;

		HardTokenData hardTokenData = null;
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
		try{
			hardTokenData = hardTokenSession.getHardToken(admin, hardTokenSN, viewPUKData);
			if(hardTokenData == null){
				throw new HardTokenDoesntExistsException("Error, hard token with SN " + hardTokenSN + " doesn't exist.");
			}
			ejbhelper.isAuthorizedToHardTokenData(admin, hardTokenData.getUsername(), viewPUKData);
		}catch(AuthorizationDeniedException e){
			boolean genNewRequest = false;
			if(WebServiceConfiguration.getApprovalForHardTokenData()){
				// Check Approvals
				// Exists an GenTokenCertificates
					Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
					UserDataVO userData = userAdminSession.findUser(intAdmin, hardTokenData.getUsername());
					if (userData == null) {
						String msg = intres.getLocalizedMessage("ra.errorentitynotexist", hardTokenData.getUsername());            	
						throw new NotFoundException(msg);
					}
					int caid = userData.getCAId();
					caAdminSession.verifyExistenceOfCA(caid);
					ar = new GenerateTokenApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenData.getHardToken().getLabel(),admin,null,WebServiceConfiguration.getNumberOfRequiredApprovals(),caid,userData.getEndEntityProfileId());
					int status = ApprovalDataVO.STATUS_REJECTED; 					
					try{
					  if(!WebServiceConfiguration.getApprovalForGenTokenCertificates()){
						  throw new ApprovalException("");
					  }
					  status = approvalSession.isApproved(admin, ar.generateApprovalId(), 0);
					  isApprovedStep0 =  status == ApprovalDataVO.STATUS_APPROVED;
					  
					  if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
							  || status == ApprovalDataVO.STATUS_EXPIRED
							  || status == ApprovalDataVO.STATUS_REJECTED){
						  throw new ApprovalException("");
					  }
					}catch(ApprovalException e2){
						// GenTokenCertificates approval doesn't exists, try a getHardTokenData request
						if(!WebServiceConfiguration.getApprovalForHardTokenData()){
							  throw new AuthorizationDeniedException("JaxWS isn't configured for getHardTokenData approvals.");
						}
						ar = new ViewHardTokenDataApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenSN, true,admin,null,WebServiceConfiguration.getNumberOfRequiredApprovals(),userData.getCAId(),userData.getEndEntityProfileId());
						try{
						  status = approvalSession.isApproved(admin, ar.generateApprovalId());
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
								approvalSession.addApprovalRequest(admin, ar, raAdminSession.getCachedGlobalConfiguration(admin));
							  throw new WaitingForApprovalException("Adding approval to view hard token data with id " + ar.generateApprovalId(), ar.generateApprovalId());
							}catch(ApprovalException e4){
								throw EjbcaWSHelper.getEjbcaException(e4, logger, ErrorCode.APPROVAL_ALREADY_EXISTS, null);
							}
						}
					}		
			}else{
				throw e;
			}
		}
		
		if(ar != null && isRejectedStep0){
			throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " have been rejected.");
		}
		
		if(ar != null && ! isApprovedStep0){
			throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
		}
		
			Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(admin, hardTokenSN);

			if(onlyValidCertificates){
				certs = ejbhelper.returnOnlyValidCertificates(admin, certs);
			}

			retval = ejbhelper.convertHardTokenToWS(hardTokenData,certs,viewPUKData);		

			if(ar != null){
				try {
					approvalSession.markAsStepDone(admin, ar.generateApprovalId(), 0);
				} catch (ApprovalException e) {
					throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, null);
				}
			}
		} catch (EJBException e) {
			throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
			throw EjbcaWSHelper.getInternalException(e, logger);*/
		} catch( RuntimeException t ) {
        	logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
        	throw t;
		} finally {
        	logger.writeln();
        	logger.flush();
		}

		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenDatas(java.lang.String)
	 */
	public List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        final Admin admin = ejbhelper.getAdmin();
        logAdminName(admin,logger);
        try {
            return getHardTokenDatas(admin,username, viewPUKData, onlyValidCertificates, logger);
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
	
	private List<HardTokenDataWS> getHardTokenDatas(Admin admin, String username, boolean viewPUKData, boolean onlyValidCertificates, IPatternLogger logger)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		List<HardTokenDataWS> retval = new  ArrayList<HardTokenDataWS>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);

		try {
			ejbhelper.isAuthorizedToHardTokenData(admin, username, viewPUKData);

			Collection<HardTokenData> hardtokens = hardTokenSession.getHardTokens(admin, username, viewPUKData);
			Iterator<HardTokenData> iter = hardtokens.iterator();
			while(iter.hasNext()){
				HardTokenData next = (HardTokenData) iter.next();
				int caid = next.getSignificantIssuerDN().hashCode();
				caAdminSession.verifyExistenceOfCA(caid);
				authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
				Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(admin, next.getTokenSN());
				if(onlyValidCertificates){
					certs = ejbhelper.returnOnlyValidCertificates(admin, certs);
				}
				retval.add(ejbhelper.convertHardTokenToWS(next,certs, viewPUKData));
			}
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
		} 

		return retval;
	}





	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#republishCertificate(java.lang.String, java.lang.String)
	 */
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException, PublisherException, EjbcaException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try{
			String bcIssuerDN = CertTools.stringToBCDNString(issuerDN);
			caAdminSession.verifyExistenceOfCA(bcIssuerDN.hashCode());
			CertReqHistory certreqhist = certificateStoreSession.getCertReqHistory(admin,new BigInteger(serialNumberInHex,16), bcIssuerDN);
			if(certreqhist == null){
				throw new PublisherException("Error: the  certificate with  serialnumber : " + serialNumberInHex +" and issuerdn " + issuerDN + " couldn't be found in database.");
			}

			ejbhelper.isAuthorizedToRepublish(admin, certreqhist.getUsername(),bcIssuerDN.hashCode());

			if(certreqhist != null){
				CertificateProfile certprofile = certificateStoreSession.getCertificateProfile(admin,certreqhist.getUserDataVO().getCertificateProfileId());
				java.security.cert.Certificate cert = certificateStoreSession.findCertificateByFingerprint(admin, certreqhist.getFingerprint());
				if(certprofile != null){
					CertificateInfo certinfo = certificateStoreSession.getCertificateInfo(admin, certreqhist.getFingerprint());
					if(certprofile.getPublisherList().size() > 0){
						if(publisherSession.storeCertificate(admin, certprofile.getPublisherList(), cert, certreqhist.getUserDataVO().getUsername(), certreqhist.getUserDataVO().getPassword(), certreqhist.getUserDataVO().getDN(),
								certinfo.getCAFingerprint(), certinfo.getStatus() , certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo.getTag(), certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), certreqhist.getUserDataVO().getExtendedinformation())){
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
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#customLog(int, String, String)
	 */
	public void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try{
	        // Check authorization to perform custom logging
			authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_LOG_CUSTOM_EVENTS);

			int event = LogConstants.EVENT_ERROR_CUSTOMLOG;
			switch (level) {
			case IEjbcaWS.CUSTOMLOG_LEVEL_ERROR:
				break;
			case IEjbcaWS.CUSTOMLOG_LEVEL_INFO:
				event = LogConstants.EVENT_INFO_CUSTOMLOG;
				break;
			default:
				throw EjbcaWSHelper.getEjbcaException("Illegal level "+ level + " sent to customLog call.", logger, ErrorCode.INVALID_LOG_LEVEL, null);
			}

			java.security.cert.Certificate logCert = null;
			if(certificate != null){
				logCert = CertificateHelper.getCertificate(certificate.getCertificateData());
			}

			int caId = admin.getCaId();
			if(cAName  != null){
				CAInfo cAInfo = caAdminSession.getCAInfoOrThrowException(admin, cAName);
				caId = cAInfo.getCAId();
			}

			String comment = type + " : " + msg;
			logSession.log(admin, caId, LogConstants.MODULE_CUSTOM, new Date(), username, (X509Certificate) logCert, event, comment);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (ClassCastException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#deleteUserDataFromSource(List, String, boolean)
	 */
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException {
		boolean ret = false;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {

			Admin admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();
			Iterator<String> iter = userDataSourceNames.iterator();
			while(iter.hasNext()){
				String nextName = iter.next();
				int id = userDataSourceSession.getUserDataSourceId(admin, nextName);
				if(id == 0){
					throw new UserDataSourceException("Error: User Data Source with name : " + nextName + " couldn't be found, aborting operation.");
				}
				userDataSourceIds.add(new Integer(id));
			}
			ret = userDataSourceSession.removeUserData(admin, userDataSourceIds, searchString, removeMultipleMatch);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }

		return ret; 
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isApproved(int)
	 */
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final Admin admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
			return approvalSession.isApproved(admin, approvalId);
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getCertificate(String, String)
	 */
	public Certificate getCertificate(String certSNinHex, String issuerDN) throws CADoesntExistsException,
		AuthorizationDeniedException, EjbcaException {
		Certificate retval = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin(true);
		String bcString = CertTools.stringToBCDNString(issuerDN);
		int caid = bcString.hashCode();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			caAdminSession.verifyExistenceOfCA(caid);
			authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
			authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);

			java.security.cert.Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(admin, issuerDN, new BigInteger(certSNinHex,16));
			if(cert != null){
				retval = new Certificate(cert);
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateEncodingException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCAs()
	 */
	public NameAndId[] getAvailableCAs() throws EjbcaException, AuthorizationDeniedException {
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin(true);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			Collection<Integer> caids = caAdminSession.getAvailableCAs(admin);
			HashMap<Integer, String> map = caAdminSession.getCAIdToNameMap(admin);
			for (Integer id : caids ) {
				String name = (String)map.get(id);
				if (name != null) {
					ret.put(name, id);
				}
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		return ejbhelper.convertTreeMapToArray(ret);
	}

    /**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAuthorizedEndEntityProfiles()
	 */
	public NameAndId[] getAuthorizedEndEntityProfiles()
			throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			Collection<Integer> ids = raAdminSession.getAuthorizedEndEntityProfileIds(admin);
			HashMap<Integer,String> idtonamemap = raAdminSession.getEndEntityProfileIdToNameMap(admin);			
			for (Integer id : ids) {
				ret.put(idtonamemap.get(id), id);
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		
		return ejbhelper.convertTreeMapToArray(ret);
	}

    /**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCertificateProfiles()
	 */
	public NameAndId[] getAvailableCertificateProfiles(int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			EndEntityProfile profile = raAdminSession.getEndEntityProfile(admin, entityProfileId);
			String value = profile.getValue(EndEntityProfile.AVAILCERTPROFILES,0);
			if (value != null) {
				String[] availablecertprofilesId = value.split(EndEntityProfile.SPLITCHAR);				
				for (String id : availablecertprofilesId) {
					int i = Integer.parseInt(id);
					ret.put(certificateStoreSession.getCertificateProfileName(admin,i), i);
				}
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		return  ejbhelper.convertTreeMapToArray(ret);
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getAvailableCAsInProfile()
	 */
	public NameAndId[] getAvailableCAsInProfile(int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
		Admin admin = ejbhelper.getAdmin();
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			EndEntityProfile profile = raAdminSession.getEndEntityProfile(admin, entityProfileId);
			Collection<String> cas = profile.getAvailableCAs(); // list of CA ids available in profile
			HashMap<Integer,String> map = caAdminSession.getCAIdToNameMap(admin);
			for (String id : cas ) {
				Integer i = Integer.valueOf(id);
				String name = (String)map.get(i);
				if (name != null) {
					ret.put(name, i);
				}
			}
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
		return ejbhelper.convertTreeMapToArray(ret);
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#createCRL(String)
	 */
	public void createCRL(String caname) throws CADoesntExistsException, ApprovalException, EjbcaException, ApprovalRequestExpiredException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
			Admin admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
			CAInfo info = caAdminSession.getCAInfoOrThrowException(admin, caname);
			CA ca = caAdminSession.getCA(admin, info.getCAId());
			crlSession.run(admin, ca);
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
		} catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		/*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getEjbcaVersion()
	 */
	public String getEjbcaVersion() {
		return GlobalConfiguration.EJBCA_VERSION;
	}
    /* (non-Javadoc)
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getPublisherQueueLength(java.lang.String)
     */
    public int getPublisherQueueLength(String name) throws EjbcaException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
            final Admin admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
            final int id = publisherSession.getPublisherId(admin, name);
            if ( id==0 ) {
                return -4;// no publisher with this name
            }
            return publisherQueueSession.getPendingEntriesCountForPublisher(id);
        } catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (EJBException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        /*} catch (RemoteException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);*/
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    private void setUserDataVOWS(UserDataVOWS userdata) {
    	userdata.setStatus(UserDataVOWS.STATUS_NEW);
    	if (userdata.getPassword() == null) {
    		userdata.setPassword("foo123");
    	}
    	userdata.setClearPwd(false);
    	userdata.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
    }

	/**
	 * @throws IllegalQueryException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest(org.ejbca.core.protocol.ws.objects.UserDataVOWS, String, int, String, String)
	 */
	public CertificateResponse certificateRequest(UserDataVOWS userdata, String requestData, int requestType, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("CertReq for user '" + userdata.getUsername() + "'.");
	        setUserDataVOWS (userdata);
	    	EjbcaWSHelper ejbcawshelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
	    	Admin admin = ejbcawshelper.getAdmin(false);
	        UserDataVO userdatavo = ejbcawshelper.convertUserDataVOWS(admin, userdata);
	        int responseTypeInt = SecConst.CERT_RES_TYPE_CERTIFICATE;
	        if (!responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
		        if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
		        	responseTypeInt = SecConst.CERT_RES_TYPE_PKCS7;
		        }
		        else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
		        	responseTypeInt = SecConst.CERT_RES_TYPE_PKCS7WITHCHAIN;
		        }
		        else{
		        	throw new NoSuchAlgorithmException ("Bad responseType:" + responseType);
		        }
	        }
	        	
	        return new CertificateResponse(responseType, certificateRequestSession.processCertReq(admin, userdatavo, requestData, requestType, hardTokenSN, responseTypeInt));
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} catch (InvalidKeyException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY, Level.ERROR);
		} catch (IllegalKeyException e) {
			// Don't log a bad error for this (user's key length too small)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.ILLEGAL_KEY, Level.DEBUG);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
		} catch (SignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.SIGNATURE_ERROR, Level.ERROR);
		} catch (SignRequestSignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, null, Level.ERROR);
		} catch (InvalidKeySpecException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY_SPEC, Level.ERROR);
		} catch (NoSuchAlgorithmException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (NoSuchProviderException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CreateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (IOException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @throws IllegalQueryException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#softTokenRequest(org.ejbca.core.protocol.ws.objects.UserDataVOWS, String, String, String)
	 */
	public KeyStore softTokenRequest(UserDataVOWS userdata, String hardTokenSN, String keyspec, String keyalg)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("Soft token req for user '" + userdata.getUsername() + "'.");
	        userdata.setStatus(UserDataVOWS.STATUS_NEW);
	        userdata.setClearPwd(true);
	    	EjbcaWSHelper ejbcawshelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, certificateStoreSession, hardTokenSession, raAdminSession, userAdminSession);
	    	Admin admin = ejbcawshelper.getAdmin(false);
	        UserDataVO userdatavo = ejbcawshelper.convertUserDataVOWS(admin, userdata);
	        boolean createJKS = userdata.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_JKS);
	        byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, userdatavo, hardTokenSN, keyspec, keyalg, createJKS);
	        // Convert encoded KeyStore to the proper return type
	        java.security.KeyStore ks;
	        if (createJKS) {
	        	ks = java.security.KeyStore.getInstance("JKS");
	        } else {
	        	ks = java.security.KeyStore.getInstance("PKCS12", "BC");
	        }
	        ks.load(new ByteArrayInputStream(encodedKeyStore), userdata.getPassword().toCharArray());
            return new KeyStore(ks, userdata.getPassword());
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( RuntimeException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} catch (InvalidKeyException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY, Level.ERROR);
		} catch (IllegalKeyException e) {
			// Don't log a bad error for this (user's key length too small)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.ILLEGAL_KEY, Level.DEBUG);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
		} catch (SignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.SIGNATURE_ERROR, Level.ERROR);
		} catch (SignRequestSignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, null, Level.ERROR);
		} catch (InvalidKeySpecException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY_SPEC, Level.ERROR);
		} catch (NoSuchAlgorithmException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (NoSuchProviderException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch( KeyStoreException e ) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (CreateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (IOException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
           throw EjbcaWSHelper.getInternalException(e, logger);
		} finally {
            logger.writeln();
            logger.flush();
        }
	}

}
