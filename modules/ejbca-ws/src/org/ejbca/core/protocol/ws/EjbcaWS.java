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
package org.ejbca.core.protocol.ws;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.jws.WebService;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509Principal;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebServiceConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionWSBridgeSessionLocal;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.logger.TransactionLogger;
import org.ejbca.core.protocol.ws.logger.TransactionTags;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.core.protocol.ws.objects.ExtendedInformationWS;
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
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.KeyValuePair;
import org.ejbca.util.passgen.AllPrintableCharPasswordGenerator;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implementor of the IEjbcaWS interface.
 * Keep this class free of other helper methods, and implement them in the helper classes instead.
 * 
 * The WebService name below is important because it determines the webservice URL on JBoss 7.1.
 * 
 * @version $Id$
 */
@Stateless
@WebService(name="EjbcaWS", serviceName="EjbcaWSService", targetNamespace="http://ws.protocol.core.ejbca.org/", portName="EjbcaWSPort")	//portName="EjbcaWSPort" default 
public class EjbcaWS implements IEjbcaWS {
	@Resource
	private WebServiceContext wsContext;	

    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private AccessControlSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateRequestSessionLocal certificateRequestSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private SignSessionLocal signSession;

    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;
    @EJB
    private WebAuthenticationProviderSessionLocal webAuthenticationSession;
    @EJB 
    private EnterpriseEditionWSBridgeSessionLocal enterpriseWSBridgeSession;

	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;
	
	private static final Logger log = Logger.getLogger(EjbcaWS.class);	
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private void logAdminName(final AuthenticationToken admin, final IPatternLogger logger) {
        // Log certificate info
        final X509Certificate cert = ((X509CertificateAuthenticationToken)admin).getCertificate();
        logger.paramPut(TransactionTags.ADMIN_DN.toString(), cert.getSubjectDN().toString());
        logger.paramPut(TransactionTags.ADMIN_ISSUER_DN.toString(), cert.getIssuerDN().toString());
        
        // Log IP address
        MessageContext msgctx = wsContext.getMessageContext();
        HttpServletRequest request = (HttpServletRequest)msgctx.get(MessageContext.SERVLET_REQUEST);
        logger.paramPut(TransactionTags.ADMIN_REMOTE_IP.toString(), request.getRemoteAddr());
        logger.paramPut(TransactionTags.ADMIN_FORWARDED_IP.toString(), StringTools.getCleanXForwardedFor(request.getHeader("X-Forwarded-For")));
    }
    /**
	 * @throws IllegalQueryException 
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#editUser(org.ejbca.core.protocol.ws.objects.UserDataVOWS)
	 */
	public void editUser(final UserDataVOWS userdata)
			throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
        	final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        	final AuthenticationToken admin = ejbhelper.getAdmin();
        	logAdminName(admin,logger);
        	final EndEntityInformation endEntityInformation = ejbhelper.convertUserDataVOWS(admin, userdata);
            if (endEntityManagementSession.existsUser(endEntityInformation.getUsername())) {
            	if (log.isDebugEnabled()) {
            		log.debug("User " + userdata.getUsername() + " exists, update the userdata. New status of user '"+userdata.getStatus()+"'." );				  
            	}
            	endEntityManagementSession.changeUser(admin,endEntityInformation,userdata.isClearPwd(), true);
            } else {
            	if (log.isDebugEnabled()) {
            		log.debug("New User " + userdata.getUsername() + ", adding userdata. New status of user '"+userdata.getStatus()+"'." );
            	}
            	endEntityManagementSession.addUserFromWS(admin,endEntityInformation,userdata.isClearPwd());
            }
		} catch (UserDoesntFullfillEndEntityProfile e) {
			log.debug(e.toString());
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
			throw e;
		} catch (AuthorizationDeniedException e) {
            final String errorMessage = "AuthorizationDeniedException when editing user "+userdata.getUsername()+": "+e.getMessage();
			log.info(errorMessage);
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorMessage);
			throw e;
		} catch (EndEntityExistsException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_ALREADY_EXISTS, Level.INFO);
        } catch (RuntimeException e) {	// ClassCastException, EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
		} finally {
		    logger.writeln();
            logger.flush();
        }
	}

	/**
	 * @throws EndEntityProfileNotFoundException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findUser(org.ejbca.core.protocol.ws.objects.UserMatch)
	 */
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public List<UserDataVOWS> findUser(UserMatch usermatch) throws AuthorizationDeniedException, IllegalQueryException, EjbcaException, EndEntityProfileNotFoundException {		
    	List<UserDataVOWS> retval = null;
    	if (log.isDebugEnabled()) {
            log.debug("Find user with match '"+usermatch.getMatchvalue()+"'.");
    	}
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
        	final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        	final AuthenticationToken admin = ejbhelper.getAdmin();
        	logAdminName(admin,logger);
        	final Query query = ejbhelper.convertUserMatch(admin, usermatch);		  		  
        	final Collection<EndEntityInformation> result = endEntityManagementSession.query(admin, query, null,null, MAXNUMBEROFROWS, AccessRulesConstants.VIEW_END_ENTITY); // also checks authorization
        	if (result.size() > 0) {
        		retval = new ArrayList<UserDataVOWS>(result.size());
        		for (final EndEntityInformation userdata : result) {
        			retval.add(ejbhelper.convertEndEntityInformation(userdata));
        		}
        	}
        } catch (CesecoreException e) {
        	// Convert cesecore exception to EjbcaException
        	EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
        } catch (RuntimeException e) {	// ClassCastException, EJBException ...
        	throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
        	logger.writeln();
        	logger.flush();
        }
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findCerts(java.lang.String, boolean)
	 */
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public List<Certificate> findCerts(String username, boolean onlyValid) throws AuthorizationDeniedException, EjbcaException {
		if (log.isDebugEnabled()) {
	        log.debug("Find certs for user '"+username+"'.");
		}
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		List<Certificate> retval = new ArrayList<Certificate>(0);
		try {
			final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			final AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
            // Check authorization on current CA and profiles and view_end_entity by looking up the end entity
            if (endEntityAccessSession.findUser(admin,username) == null) {
                if (log.isDebugEnabled()) {
                    log.debug(intres.getLocalizedMessage("ra.errorentitynotexist", username));              
                }
            }
            // Even if there is no end entity, it might be the case that we don't store UserData, so we still need to check CertificateData 
            final long now = System.currentTimeMillis();
            Collection<java.security.cert.Certificate> certs;
            if (onlyValid) {
                // We will filter out not yet valid certificates later on, but we as the database to not return any expired certificates
                certs = certificateStoreSession.findCertificatesByUsernameAndStatusAfterExpireDate(username, CertificateConstants.CERT_ACTIVE, now);
            } else {
                certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
            }
            retval = ejbhelper.returnAuthorizedCertificates(admin, certs, onlyValid, now);
        } catch (RuntimeException e) {	// EJBException ...
            throw EjbcaWSHelper.getInternalException(e, logger);
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
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			if (endEntityAccessSession.findUser(admin, username) != null) { // checks authorization on CA and profiles and view_end_entity
				Collection<java.security.cert.Certificate> certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
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
							Collection<java.security.cert.Certificate> cacerts = certificateStoreSession.findCertificatesBySubject(issuerDN);
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
		} catch (CertificateEncodingException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		if (log.isTraceEnabled()) {
			log.trace("<getLastCertChain: "+username);
		}
		return retval;
	}
	
	@Override
	public void createCryptoToken(String tokenName, String tokenType, String activationPin, boolean autoActivate, 
	        List<KeyValuePair> cryptotokenProperties) throws AuthorizationDeniedException, EjbcaException  {
	    
	    EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, 
	            certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, 
	            hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(ejbhelper.getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.createCryptoToken(ejbhelper.getAdmin(), tokenName, tokenType, activationPin, autoActivate, 
	                cryptotokenProperties);
	    } catch (AuthorizationDeniedException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw EjbcaWSHelper.getInternalException(e, logger);
	    } catch (NoSuchSlotException e) {
	        throw EjbcaWSHelper.getInternalException(e, TransactionLogger.getPatternLogger());
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void generateCryptoTokenKeys(String cryptoTokenName, String keyPairAlias, String keySpecification) 
	        throws AuthorizationDeniedException, EjbcaException {
	    EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, 
	            certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, 
	            hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(ejbhelper.getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.generateCryptoTokenKeys(ejbhelper.getAdmin(), cryptoTokenName, keyPairAlias, keySpecification);
	    } catch (AuthorizationDeniedException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw EjbcaWSHelper.getInternalException(e, logger);
	    } catch (InvalidKeyException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.INVALID_KEY, Level.INFO);
	    } catch (InvalidAlgorithmParameterException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.INVALID_KEY_SPEC, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void createCA(String caname, String cadn, String catype, long validityInDays, String certprofile, 
	        String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping, 
	        List<KeyValuePair> caProperties) throws EjbcaException, AuthorizationDeniedException {
	    
	    EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, 
	            certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, 
	            hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(ejbhelper.getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.createCA(ejbhelper.getAdmin(), caname, cadn, catype, validityInDays, certprofile, 
	                signAlg, signedByCAId, cryptoTokenName, purposeKeyMapping, caProperties);
	    } catch (AuthorizationDeniedException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw EjbcaWSHelper.getInternalException(e, logger);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void addSubjectToRole(String roleName, String caName, String matchWith, String matchType, 
	        String matchValue) throws EjbcaException, AuthorizationDeniedException {
    
	    EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, 
	            certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, 
	            hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(ejbhelper.getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.addSubjectToRole(ejbhelper.getAdmin(), roleName, caName, matchWith, matchType, matchValue);
	    } catch (AuthorizationDeniedException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw EjbcaWSHelper.getInternalException(e, logger);    
	    } catch (RoleNotFoundException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.ROLE_DOES_NOT_EXIST, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void removeSubjectFromRole(String roleName, String caName, String matchWith, String matchType, 
	        String matchValue) throws EjbcaException, AuthorizationDeniedException {
    
	    EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, 
	            certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, 
	            hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(ejbhelper.getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.removeSubjectFromRole(ejbhelper.getAdmin(), roleName, caName, matchWith, matchType, matchValue);
	    } catch (AuthorizationDeniedException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw EjbcaWSHelper.getInternalException(e, logger);    
	    } catch (RoleNotFoundException e) {
	        throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.ROLE_DOES_NOT_EXIST, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}
	
	public List<Certificate> getCertificatesByExpirationTime(long days, int maxNumberOfResults) throws EjbcaException {
	    Date findDate = new Date();
	    long millis = (days * 24 * 60 * 60 * 1000);
	    findDate.setTime(findDate.getTime() + millis);
	    Collection<java.security.cert.Certificate> certs = certificateStoreSession.findCertificatesByExpireTimeWithLimit(findDate, maxNumberOfResults);

	    ArrayList<Certificate> ret = new ArrayList<Certificate>();
	    for(java.security.cert.Certificate cert : certs) {
	        try {
                ret.add(new Certificate(cert));
            } catch (CertificateEncodingException e) {
                throw EjbcaWSHelper.getInternalException(e, TransactionLogger.getPatternLogger());
            }
	    }
	    return ret;
	}
	
	public List<Certificate> getCertificatesByExpirationTimeAndIssuer(long days, String issuer, int maxNumberOfResults) throws EjbcaException {
	    Date findDate = new Date();
	    long millis = (days * 24 * 60 * 60 * 1000);
	    findDate.setTime(findDate.getTime() + millis);
	    Collection<java.security.cert.Certificate> certs = certificateStoreSession.findCertificatesByExpireTimeAndIssuerWithLimit(findDate, issuer, maxNumberOfResults);
	    
	    ArrayList<Certificate> ret = new ArrayList<Certificate>();
        for(java.security.cert.Certificate cert : certs) {
            try {
                ret.add(new Certificate(cert));
            } catch (CertificateEncodingException e) {
                throw EjbcaWSHelper.getInternalException(e, TransactionLogger.getPatternLogger());
            }
        }
	    return ret;
	}
	
	public List<Certificate> getCertificatesByExpirationTimeAndType(long days, int certificateType, int maxNumberOfResults) throws EjbcaException {
	    Date findDate = new Date();
	    long millis = (days * 24 * 60 * 60 * 1000);
	    findDate.setTime(findDate.getTime() + millis);
	    Collection<java.security.cert.Certificate> certs = certificateStoreSession.findCertificatesByExpireTimeAndTypeWithLimit(findDate, certificateType, maxNumberOfResults);
	    
	    ArrayList<Certificate> ret = new ArrayList<Certificate>();
        for(java.security.cert.Certificate cert : certs) {
            try {
                ret.add(new Certificate(cert));
            } catch (CertificateEncodingException e) {
                throw EjbcaWSHelper.getInternalException(e, TransactionLogger.getPatternLogger());
            }
        }
	    return ret;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#crmfRequest(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse crmfRequest(String username, String password,
			String crmf, String hardTokenSN, String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    crmf, CertificateConstants.CERT_REQ_TYPE_CRMF, hardTokenSN, responseType, logger));
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (RuntimeException e) {	// ClassCastException, EJBException ...
            throw EjbcaWSHelper.getInternalException(e, logger);
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
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    spkac, CertificateConstants.CERT_REQ_TYPE_SPKAC, hardTokenSN, responseType, logger));
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (RuntimeException e) {	// EJBException ...
            throw EjbcaWSHelper.getInternalException(e, logger);
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
	 * @throws AuthorizationDeniedException 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	private PublicKey getCVPublicKey(AuthenticationToken admin, java.security.cert.Certificate cert) throws CADoesntExistsException, AuthorizationDeniedException {
		PublicKey pk = cert.getPublicKey();
		if (pk instanceof PublicKeyEC) {
			// The public key of IS and DV certificate do not have any EC parameters so we have to do some magic to get a complete EC public key
			// First get to the CVCA certificate that has the parameters
			CAInfo info = caSession.getCAInfo(admin, CertTools.getIssuerDN(cert).hashCode());
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
			EjbcaException, CesecoreException, ApprovalException, WaitingForApprovalException, SignRequestException, CertificateExpiredException {
		log.trace(">cvcRequest");
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();

		// If password is empty we can generate a big random one to use instead
		if (StringUtils.isEmpty(password)) {
			AllPrintableCharPasswordGenerator gen = new AllPrintableCharPasswordGenerator();
			password = gen.getNewPassword(15, 20);
			log.debug("Using a long random password");
		}
		// get and old status that we can remember so we can reset status if this fails in the last step
		int olduserStatus = EndEntityConstants.STATUS_GENERATED;
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
			 EndEntityInformation user = endEntityAccessSession.findUser(admin, username);
			// See if this user already exists.
			// We allow renewal of certificates for IS's that are not revoked
			// In that case look for it's last old certificate and try to authenticate the request using an outer signature.
			// If this verification is correct, set status to NEW and continue process the request.
			if (user != null) {
				olduserStatus = user.getStatus();
				// If user is revoked, we can not proceed
				if ( (olduserStatus == EndEntityConstants.STATUS_REVOKED) || (olduserStatus == EndEntityConstants.STATUS_HISTORICAL) ) {
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
					Collection<java.security.cert.Certificate> oldcerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
					if (oldcerts != null) {
						log.debug("Found "+oldcerts.size()+" old certificates for user "+username);
						Iterator<java.security.cert.Certificate> iterator = oldcerts.iterator(); 
						while (iterator.hasNext()) {
							java.security.cert.Certificate cert = iterator.next();
							PublicKey pk = getCVPublicKey(admin, cert);
							CVCertificate innerreq = authreq.getRequest();
							checkInnerCollision(pk, innerreq, holderRef.getConcatenated()); // Throws AuthorizationDeniedException
						}
					}

					boolean verifiedOuter = false; // So we can throw an error if we could not verify
					if (StringUtils.equals(holderRef.getMnemonic(), caRef.getMnemonic()) && StringUtils.equals(holderRef.getCountry(), caRef.getCountry())) {
						log.debug("Authenticated request is self signed, we will try to verify it using user's old certificate.");
						Collection<java.security.cert.Certificate> certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username));
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
									PublicKey pk = getCVPublicKey(admin, cert);
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
						try {
						    CAInfo info = caSession.getCAInfo(admin, CertTools.stringToBCDNString(dn).hashCode());
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
						}catch (CADoesntExistsException e) {
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
			byte[] response = processCertReq(username, password, cvcreq, CertificateConstants.CERT_REQ_TYPE_CVC, null, CertificateHelper.RESPONSETYPE_CERTIFICATE, logger);
			CertificateResponse ret = new CertificateResponse(CertificateHelper.RESPONSETYPE_CERTIFICATE, response);
			byte[] b64cert = ret.getData();
			CVCertificate certObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
			java.security.cert.Certificate iscert = new CardVerifiableCertificate(certObject); 
			ArrayList<Certificate> retval = new ArrayList<Certificate>();
			retval.add(new Certificate((java.security.cert.Certificate)iscert));
			// Get the certificate chain
			if (user != null) {
				int caid = user.getCAId();
				caSession.verifyExistenceOfCA(caid);
				Collection<java.security.cert.Certificate> certs = signSession.getCertificateChain(caid);
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
		} catch (ServiceLocatorException e) {
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
		    throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (FinderException e) {
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
        } catch (RuntimeException e) {	// EJBException, ...
			ejbhelper.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw EjbcaWSHelper.getInternalException(e, logger);
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
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();
		byte[] ret = null;
		try {
			ret = ejbhelper.caRenewCertRequest(ejbhelper, admin, caname, cachain, regenerateKeys, usenextkey, activatekey, keystorepwd);
		} catch (CertPathValidatorException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CryptoTokenOfflineException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CryptoTokenAuthenticationFailedException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, null);
		}
		if (log.isTraceEnabled()) {
			log.trace("<caRenewCertRequest");
		}
		return ret;
	} // caRenewCertRequest

	/**
	 * @throws CesecoreException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caCertResponse
	 */
	public void caCertResponse(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException {
		log.trace(">caCertResponse");
		log.info("Import certificate response for CA "+caname+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();
		try {
			ejbhelper.caCertResponse(ejbhelper, admin, caname, cert, cachain, keystorepwd, false);
		} catch (CertPathValidatorException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CryptoTokenOfflineException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CryptoTokenAuthenticationFailedException e) {
		    throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, null);
		}
		log.trace("<caCertResponse");
	} // caCertResponse
	
	/**
     * @throws CesecoreException 
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caCertResponseForRollover
     */
    public void caCertResponseForRollover(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException {
        log.trace(">caCertResponseWithRollover");
        log.info("Import certificate response with rollover for CA "+caname+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
        EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        AuthenticationToken admin = ejbhelper.getAdmin();
        try {
            ejbhelper.caCertResponse(ejbhelper, admin, caname, cert, cachain, keystorepwd, true);
        } catch (CertPathValidatorException e) {
            throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
        } catch (CryptoTokenOfflineException e) {
            throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (RuntimeException e) {  // EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, null);
        }
        log.trace("<caCertResponseWithRollover");
    } // caCertResponse
    
    /**
     * @throws EjbcaException 
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#rolloverCACert
     */
    public void rolloverCACert(String caname) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        log.trace(">rolloverCACert");
        log.info("Rollover to next certificate for CA "+caname);
        EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        AuthenticationToken admin = ejbhelper.getAdmin();
        try {
            ejbhelper.rolloverCACert(ejbhelper, admin, caname);
        } catch (CryptoTokenOfflineException e) {
            throw EjbcaWSHelper.getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (RuntimeException e) {  // EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, null);
        }
        log.trace("<rolloverCACert");
    } // rolloverCACert

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs10Request(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public CertificateResponse pkcs10Request(final String username, final String password, final String pkcs10, final String hardTokenSN, final String responseType)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	    	if (log.isDebugEnabled()) {
	    		log.debug("PKCS10 from user '"+username+"'.");
	    	}
	        return new CertificateResponse(responseType, processCertReq(username, password,
	                                                                    pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, hardTokenSN, responseType, logger));
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
	
	private byte[] processCertReq(final String username, final String password, final String req, final int reqType,
			final String hardTokenSN, final String responseType, final IPatternLogger logger) throws EjbcaException, CesecoreException, CADoesntExistsException, AuthorizationDeniedException {
		byte[] retval = null;
		try {
            final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession,
                    certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession,
                    webAuthenticationSession, cryptoTokenManagementSession);
			final AuthenticationToken admin = ejbhelper.getAdmin();			  
            logAdminName(admin,logger);
			// check authorization to CAID
			final EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
			if (userdata == null) {
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
			    String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
				throw new NotFoundException(msg);
			}
			final int caid = userdata.getCAId();
			caSession.verifyExistenceOfCA(caid);
			// Check tokentype
			if (userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
				throw EjbcaWSHelper.getEjbcaException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests",
                                        logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
			}
            // Authorization for {StandardRules.CAACCESS.resource() +caid, StandardRules.CREATECERT.resource()} is done in the 
            // CertificateCreateSessionBean.createCertificate call which is called in the end
			RequestMessage imsg = RequestMessageUtils.getRequestMessageFromType(username, password, req, reqType);
			if (imsg != null) {
				retval = getCertResponseFromPublicKey(admin, imsg, hardTokenSN, responseType);
			}
		} catch (CertificateExtensionException e) {
		    throw EjbcaWSHelper.getInternalException(e, logger);
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
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, ErrorCode.BAD_REQUEST_SIGNATURE, Level.ERROR);
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
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
		} 
		return retval;
	}


    private byte[] getCertResponseFromPublicKey(final AuthenticationToken admin, final RequestMessage msg, final String hardTokenSN,
            final String responseType) throws AuthorizationDeniedException, CertificateEncodingException, EjbcaException, CesecoreException,
            CertificateExtensionException, CertificateParsingException {
        byte[] retval = null;
        final ResponseMessage resp = signSession.createCertificate(admin, msg, X509ResponseMessage.class, null);
        final java.security.cert.Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), java.security.cert.Certificate.class);
        if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
            retval = cert.getEncoded();
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
            retval = signSession.createPKCS7(admin, (X509Certificate) cert, false);
        } else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
            retval = signSession.createPKCS7(admin, (X509Certificate) cert, true);
        }
        if (hardTokenSN != null) {
            hardTokenSession.addHardTokenCertificateMapping(admin, hardTokenSN, cert);
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
			  EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			  AuthenticationToken admin = ejbhelper.getAdmin();
              logAdminName(admin,logger);

			  // check CAID
			  EndEntityInformation userdata = endEntityAccessSession.findUser(admin,username);
			  if(userdata == null){
			      log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				  throw new NotFoundException(intres.getLocalizedMessage("ra.wrongusernameorpassword"));
			  }
			  int caid = userdata.getCAId();
			  caSession.verifyExistenceOfCA(caid);
			  if(!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() +caid, StandardRules.CREATECERT.resource())) {
				  final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid +
				          "," + StandardRules.CREATECERT.resource(), null);
				  throw new AuthorizationDeniedException(msg);
			  }
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_P12){
                  throw EjbcaWSHelper.getEjbcaException("Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests", logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
			  }

			  boolean usekeyrecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
			  log.debug("usekeyrecovery: "+usekeyrecovery);
			  boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery &&  (userdata.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
			  log.debug("userdata.getKeyRecoverable(): "+userdata.getKeyRecoverable());
			  log.debug("userdata.getStatus(): "+userdata.getStatus());
			  log.debug("savekeys: "+savekeys);
			  boolean loadkeys = (userdata.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
			  log.debug("loadkeys: "+loadkeys);
			  int endEntityProfileId = userdata.getEndEntityProfileId();
			  EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
			  boolean reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
			  log.debug("reusecertificate: "+reusecertificate);

			  try {
				  GenerateToken tgen = new GenerateToken(authenticationSession, endEntityAccessSession, endEntityManagementSession, caSession, keyRecoverySession, signSession);
				  java.security.KeyStore pkcs12 = tgen.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, false, loadkeys, savekeys, reusecertificate, endEntityProfileId);
                  final KeyStore retval = new KeyStore(pkcs12, password);
				  final Enumeration<String> en = pkcs12.aliases();
				  final String alias = en.nextElement();
                  final X509Certificate cert = (X509Certificate) pkcs12.getCertificate(alias);
                  if ( (hardTokenSN != null) && (cert != null) ) {
                      hardTokenSession.addHardTokenCertificateMapping(admin,hardTokenSN,cert);                 
                  }
                  return retval;
              } catch (AuthLoginException e) { // NOPMD, since we catch wide below
                  throw e;
              } catch (AuthStatusException e) { // NOPMD, since we catch wide below
                  throw e;
              } catch (Exception e) {
                  throw EjbcaWSHelper.getInternalException(e, logger);
			  } 
			} catch (ClassCastException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);
			} catch (EJBException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);
			} catch (AuthStatusException e) {
				// Don't log a bad error for this (user wrong status)
                throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
			} catch (AuthLoginException e) {
                throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
	        } catch (RuntimeException e) {	// EJBException, ...
	            throw EjbcaWSHelper.getInternalException(e, logger);
            } finally {
                logger.writeln();
                logger.flush();
			}
	}

	private void revokeCert(final String issuerDN, final String certificateSN, final int reason, Date date, IPatternLogger logger) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException {
		if (log.isDebugEnabled()) {
			log.debug("Revoke cert with serial number '"+certificateSN+"' from issuer '"+issuerDN+"' with reason '"+reason+"'.");
		}
		try {
			final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			final AuthenticationToken admin = ejbhelper.getAdmin();
			logAdminName(admin,logger);
			final int caid = CertTools.stringToBCDNString(issuerDN).hashCode();
			caSession.verifyExistenceOfCA(caid);
			final BigInteger serno = new BigInteger(certificateSN, 16);
			// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
			// that was permanently revoked
			endEntityManagementSession.revokeCert(admin, serno, date, issuerDN, reason, true);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (RuntimeException e) {	// EJBException, ClassCastException, ...
			throw EjbcaWSHelper.getInternalException(e, logger);
		}
	}

	@Override
	public void revokeCert(final String issuerDN, final String certificateSN, final int reason) throws
	CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			try {
				revokeCert( issuerDN, certificateSN, reason, (Date)null, logger);
			} catch (RevokeBackDateNotAllowedForProfileException e) {
				throw new Error("This is should not happen since there is no back dating.",e);
			}
		} finally {
			logger.writeln();
			logger.flush();
		}
	}

	@Override
	public void revokeCertBackdated(final String issuerDN, final String certificateSN, final int reason, String sDate) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException, DateNotValidException {
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			if ( sDate==null ) {
				revokeCert(issuerDN, certificateSN, reason);
				return;
			}
			final Date date;
			try {
				date = DatatypeConverter.parseDateTime(sDate).getTime();
			} catch (IllegalArgumentException e) {
				throw new DateNotValidException( intres.getLocalizedMessage("ra.bad.date", sDate) );
			}
			if ( date.after(new Date()) ) {
				throw new DateNotValidException("Revocation date in the future: '"+sDate+"'.");
			}
			revokeCert(issuerDN, certificateSN, reason, date, logger);
		} finally {
			logger.writeln();
			logger.flush();
		}
	}


    @Override
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

			// check username
			EndEntityInformation userdata = endEntityAccessSession.findUser(admin,username);
			if(userdata == null){
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");            	
				throw new NotFoundException(msg);
			}
			// Check caid
			int caid = userdata.getCAId();
			caSession.verifyExistenceOfCA(caid);
			if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() +caid)) {
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
		        throw new AuthorizationDeniedException(msg);
			}
			if (deleteUser) {
				endEntityManagementSession.revokeAndDeleteUser(admin,username,reason);
			} else {
				endEntityManagementSession.revokeUser(admin,username,reason);
			}
		}  catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (RemoveException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public void keyRecoverNewest(String username) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException {
		log.trace(">keyRecoverNewest");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

            boolean usekeyrecovery =((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();  
            if(!usekeyrecovery){
				throw EjbcaWSHelper.getEjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.",
                                        logger, ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, null);
            }   
			EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
			if(userdata == null){
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");            	
				throw new NotFoundException(msg);
			}
			if(keyRecoverySession.isUserMarked(username)){
				// User is already marked for recovery.
				return;                     
			}
			// check CAID
			int caid = userdata.getCAId();
			caSession.verifyExistenceOfCA(caid);
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
		        throw new AuthorizationDeniedException(msg);
            }

			// Do the work, mark user for key recovery
			endEntityManagementSession.prepareForKeyRecovery(admin, userdata.getUsername(), userdata.getEndEntityProfileId(), null);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		log.trace("<keyRecoverNewest");
	}

	@Override
    public void keyRecover(String username, String certSNinHex, String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">keyRecover");
        }
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
            final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
            final AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);

            final boolean usekeyrecovery = ((GlobalConfiguration)globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();  
            if(!usekeyrecovery){
                throw EjbcaWSHelper.getEjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.",
                                        logger, ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, null);
            }   
            final EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
            if(userdata == null){
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
                final String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");                
                throw new NotFoundException(msg);
            }
            if(keyRecoverySession.isUserMarked(username)){
                // User is already marked for recovery.
                return;                     
            }
            // check CAID
            final int caid = userdata.getCAId();
            caSession.verifyExistenceOfCA(caid);
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
                throw new AuthorizationDeniedException(msg);
            }
            
            // find certificate to recover
            final Certificate wsCert = getCertificate(certSNinHex, issuerDN);
            if (wsCert == null) {
                throw new EjbcaException(ErrorCode.CERT_PATH_INVALID);
            }
            java.security.cert.Certificate cert = null;
            try {
                cert = CertificateHelper.getCertificate(wsCert.getCertificateData());
            } catch (CertificateException e) {
                throw EjbcaWSHelper.getInternalException(e, logger);
            }
            // Do the work, mark user for key recovery
            endEntityManagementSession.prepareForKeyRecovery(admin, userdata.getUsername(), userdata.getEndEntityProfileId(), cert);
        } catch (RuntimeException e) {  // EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        if (log.isTraceEnabled()) {
            log.trace("<keyRecover");
        }
    }
	
    @Override
	public void revokeToken(String hardTokenSN, int reason)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
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
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
	
	private void revokeToken(AuthenticationToken admin, String hardTokenSN, int reason, IPatternLogger logger) throws CADoesntExistsException, AuthorizationDeniedException,
			NotFoundException, EjbcaException, AlreadyRevokedException, ApprovalException, WaitingForApprovalException {
		ApprovalException lastApprovalException = null;
		WaitingForApprovalException lastWaitingForApprovalException = null;
		AuthorizationDeniedException lastAuthorizationDeniedException = null;
		AlreadyRevokedException lastAlreadyRevokedException = null;
		boolean success = false;
		try{
            logAdminName(admin,logger);
			Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(hardTokenSN);
			Iterator<java.security.cert.Certificate> iter = certs.iterator();
			while(iter.hasNext()){
				X509Certificate next = (X509Certificate) iter.next();
				// check that admin is authorized to CA
				int caid = CertTools.getIssuerDN(next).hashCode();
				caSession.verifyExistenceOfCA(caid);
				if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() +caid)) {
		            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
			        throw new AuthorizationDeniedException(msg);
				}
				try {
					// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
					// that was permanently revoked
					endEntityManagementSession.revokeCert(admin,CertTools.getSerialNumber(next),CertTools.getIssuerDN(next),reason);
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
		} catch (AlreadyRevokedException e) {
            throw EjbcaWSHelper.getEjbcaException(e.getMessage(), logger, ErrorCode.CERT_WRONG_STATUS, null);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
		} 
	}

    @Override
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();

		try{
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		  AuthenticationToken admin = ejbhelper.getAdmin();		  
          logAdminName(admin,logger);

		  // check that admin is autorized to CA
		  int caid = CertTools.stringToBCDNString(issuerDN).hashCode();
		  caSession.verifyExistenceOfCA(caid);
		  if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() +caid)) {
			  final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
			  throw new AuthorizationDeniedException(msg);
		  }
		  
		  CertificateStatus certinfo = certificateStoreSession.getStatus(issuerDN, new BigInteger(certificateSN,16));
		  // If certificate is not available, pass this and return null
		  if(certinfo != null && !certinfo.equals(CertificateStatus.NOT_AVAILABLE)){
		    return new RevokeStatus(certinfo, issuerDN, certificateSN);
		  }
		  return null;
        } catch (DatatypeConfigurationException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}	

    @Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public boolean isAuthorized(String resource) throws EjbcaException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
            final AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			return authorizationSession.isAuthorized(admin, resource);	
		} catch (AuthorizationDeniedException ade) {
            return false;
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws UserDataSourceException, EjbcaException, AuthorizationDeniedException{
	    
		final AuthenticationToken admin;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);

		if(WebServiceConfiguration.getNoAuthorizationOnFetchUserData()){
			final AuthenticationToken tmp = ejbhelper.getAdmin(true);
			// We know client certificate is needed, so no other authentication tokens can exist
			X509Certificate admincert = ((X509CertificateAuthenticationToken)tmp).getCertificate();
			admin = new AlwaysAllowLocalAuthenticationToken(new X509Principal(admincert.getSubjectDN().getName()));
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
			            userDataSourceIds.add(Integer.valueOf(id));
			        }else{
			            log.error("Error User Data Source with name : " + name + " doesn't exist.");
			        }
			    }
			}
			{
			    final Iterator<UserDataSourceVO> iter = userDataSourceSession.fetch(admin, userDataSourceIds, searchString).iterator();
			    while(iter.hasNext()){
			        UserDataSourceVO next = iter.next();
			        retval.add(new UserDataSourceVOWS(ejbhelper.convertEndEntityInformation(next.getEndEntityInformation()),next.getIsFieldModifyableSet()));
			    }
			}
        } catch (CADoesntExistsException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.CA_NOT_EXISTS, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return retval;
	}		
	
    @Override
	public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userDataWS, List<TokenCertificateRequestWS> tokenRequests, HardTokenDataWS hardTokenDataWS, boolean overwriteExistingSN, boolean revokePreviousCards)
		throws CADoesntExistsException, AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException,UserDoesntFullfillEndEntityProfile, ApprovalException, EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException {
		final ArrayList<TokenCertificateResponseWS> retval = new ArrayList<TokenCertificateResponseWS>();

		final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin(true);
		int endEntityProfileId = 0;
		boolean hardTokenExists = false;
		boolean userExists = false;
		
		boolean approvalSuccessfullStep1 = false;
		boolean isRejectedStep1 = false;

		// Get Significant user Id
		final CAInfo significantcAInfo;
		final ArrayList<java.security.cert.Certificate> genCertificates = new ArrayList<java.security.cert.Certificate>();
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		final AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EJBCAWS.genTokenCertificates"));
		try {
			significantcAInfo = caSession.getCAInfo(intAdmin, userDataWS.getCaName());
		if(significantcAInfo == null){
			throw EjbcaWSHelper.getEjbcaException("Error the given CA : " + userDataWS.getCaName() + " could not be found.",
					logger, ErrorCode.CA_NOT_EXISTS, null);
		}
		
		EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(intAdmin, userDataWS.getUsername());
		if(endEntityInformation != null){
			endEntityProfileId = endEntityInformation.getEndEntityProfileId();
			userExists = true;
		}else{
		    try {
			endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(userDataWS.getEndEntityProfileName());	
		    } catch(EndEntityProfileNotFoundException e) {
		        throw EjbcaWSHelper.getEjbcaException("Error given end entity profile : " + userDataWS.getEndEntityProfileName() +" could not be found",
                        logger, ErrorCode.EE_PROFILE_NOT_EXISTS, null);
		    }
		}
			
		// Approval request if we require approvals to generate token certificates
		ApprovalRequest ar = null;
		if (ejbhelper.isAdmin()) {
		    final List<String> rules = new ArrayList<String>();
            rules.add(StandardRules.CREATECERT.resource());
            rules.add(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS);
            rules.add(StandardRules.CAACCESS.resource() + significantcAInfo.getCAId());
            if (overwriteExistingSN) {
                rules.add(AccessRulesConstants.REGULAR_REVOKEENDENTITY);
                rules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.REVOKE_END_ENTITY);
            }
            if (userExists) {
                rules.add(AccessRulesConstants.REGULAR_EDITENDENTITY);
                rules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.EDIT_END_ENTITY);
            } else {
                rules.add(AccessRulesConstants.REGULAR_CREATEENDENTITY);
                rules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.CREATE_END_ENTITY);
            }
            String[] rulesArray = rules.toArray(new String[rules.size()]);
            if (!authorizationSession.isAuthorizedNoLogging(admin, rulesArray)) {
                final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", Arrays.toString(rulesArray), null);
                throw new AuthorizationDeniedException(msg);
            }
		} else {
		    boolean approveGenTokenCert = false; // will cause AuthorizationDeniedException
		    final String approvalProfileIdString = WebServiceConfiguration.getApprovalProfile();   
	        ApprovalProfile approvalProfile = null;
		    if(StringUtils.isNotEmpty(approvalProfileIdString) && NumberUtils.isNumber(approvalProfileIdString)) {
		        Integer approvalProfileId = Integer.valueOf(approvalProfileIdString);
		        approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
		    }
		    if(approvalProfile!=null) {
		        approveGenTokenCert = true; // arrayContainsValue(approvalProfile.getActionsRequireApproval(), ApprovalRequest.REQ_APPROVAL_GENERATE_TOKEN_CERTIFICATE);
		    }
		    
			if(approveGenTokenCert){
                    ar = new GenerateTokenApprovalRequest(userDataWS.getUsername(), userDataWS.getSubjectDN(), hardTokenDataWS.getLabel(), admin,
                            null, significantcAInfo.getCAId(), endEntityProfileId, approvalProfile);
				int status = ApprovalDataVO.STATUS_REJECTED; 					
				try{
					status = approvalSession.isApproved(admin, ar.generateApprovalId(), 1);
                    approvalSuccessfullStep1 = (status == ApprovalDataVO.STATUS_APPROVED);
                    isRejectedStep1 = (status == ApprovalDataVO.STATUS_REJECTED);
					if(status == ApprovalDataVO.STATUS_APPROVED){
						ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(intAdmin, ar.generateApprovalId());
						String originalDN = ((GenerateTokenApprovalRequest) approvalDataVO.getApprovalRequest()).getDN();
						userDataWS.setSubjectDN(originalDN); // replace requested DN with original DN to make sure nothing have changed.
					} else if (status == ApprovalDataVO.STATUS_REJECTED) {
						throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " has been rejected.");												
					} else if (status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED || status == ApprovalDataVO.STATUS_EXPIRED) {
						throw new ApprovalException("The approval for id " + ar.generateApprovalId() + " has expired.");
					} else {
						throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
					}
				}catch(ApprovalException e){
					approvalSession.addApprovalRequest(admin, ar);
					throw new WaitingForApprovalException("Approval request with id " + ar.generateApprovalId() + " have been added for approval.",ar.generateApprovalId());
				}
			}else{
				throw new AuthorizationDeniedException();
			}
		}
		
		if (ar != null && isRejectedStep1) {
		    throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " has been rejected.");
		}

		if (ar != null && !approvalSuccessfullStep1) {
		    throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " has not yet been approved", ar.generateApprovalId());
		}

		if (ar != null) {
		    // We need to create a new AuthenticationToken here that has the "name" of the admin making the request, but that 
		    // behaves like an "AlwaysAllowedAuthenticationToken". This is because the request admin does not have privileges, 
		    // but we want to log as if the requesting admin performed actions below.
		    final Set<? extends Principal> principals = admin.getPrincipals();
		    Principal p = null;
		    if (!principals.isEmpty()) {
		        p = principals.iterator().next();
		    } else {
		        final Set<?> credentials = admin.getCredentials();
		        if (!credentials.isEmpty()) {
		            final Object o = credentials.iterator().next();
		            if (o instanceof X509Certificate) {
                        final X509Certificate cert = (X509Certificate) o;
                        p = new X500Principal(cert.getSubjectDN().getName());
                    }
		        } else {
		            log.error("Admin does not have neither Principals nor Credentials");
		        }
		    }
		    admin = new AlwaysAllowLocalAuthenticationToken(p);
		}

			hardTokenExists = hardTokenSession.existsHardToken(hardTokenDataWS.getHardTokenSN());
			if(hardTokenExists){
				if(overwriteExistingSN){
					// fetch all old certificates and revoke them.
					Collection<java.security.cert.Certificate> currentCertificates = hardTokenSession.findCertificatesInHardToken(hardTokenDataWS.getHardTokenSN());
					HardTokenInformation currentHardToken = hardTokenSession.getHardToken(admin, hardTokenDataWS.getHardTokenSN(), false);
					Iterator<java.security.cert.Certificate> iter = currentCertificates.iterator();
					while(iter.hasNext()){
						java.security.cert.X509Certificate nextCert = (java.security.cert.X509Certificate) iter.next();
						try {
							endEntityManagementSession.revokeCert(admin, CertTools.getSerialNumber(nextCert), CertTools.getIssuerDN(nextCert), RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
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


			if(revokePreviousCards){
				List<HardTokenDataWS> htd = getHardTokenDatas(admin,userDataWS.getUsername(), false, true, logger);
				Iterator<HardTokenDataWS> htdIter = htd.iterator();

				while(htdIter.hasNext()) {
					HardTokenDataWS toRevoke = htdIter.next();
					try{
						  if(hardTokenDataWS.getLabel().equals(HardTokenConstants.LABEL_TEMPORARYCARD) && toRevoke.getLabel() != null && !toRevoke.getLabel().equals(HardTokenConstants.LABEL_TEMPORARYCARD)){

								// Token have extended key usage MS Logon, don't revoke it
								Iterator<java.security.cert.Certificate> revokeCerts = hardTokenSession.findCertificatesInHardToken(toRevoke.getHardTokenSN()).iterator();

								while(revokeCerts.hasNext()){
									X509Certificate next = (X509Certificate) revokeCerts.next();							 
									try{
										if(WebServiceConfiguration.getSuspendAllCertificates() || next.getExtendedKeyUsage() == null || !next.getExtendedKeyUsage().contains(KeyPurposeId.id_kp_smartcardlogon.getId())){
											endEntityManagementSession.revokeCert(admin,next.getSerialNumber(), CertTools.getIssuerDN(next), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
										}
									}catch(CertificateParsingException e){
										log.error(e);
									} catch (FinderException e) {
										log.error(e);
									}	
								}
						

						}else{
							revokeToken(admin, toRevoke.getHardTokenSN(), RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, logger);
						}
					}catch(AlreadyRevokedException e){
						// Do nothing
					}
				}
			}
		
		try{
			// Check if the userdata exist and edit/add it depending on which
			String password = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(8, 8);
			EndEntityInformation userData = ejbhelper.convertUserDataVOWS(admin, userDataWS);
			userData.setPassword(password);
			if(userExists){
				endEntityManagementSession.changeUser(admin, userData, true);
			}else{
				endEntityManagementSession.addUser(admin, userData, true);
			}

			Date bDate = new Date(System.currentTimeMillis() - (10 * 60 * 1000));
			
			Iterator<TokenCertificateRequestWS> iter = tokenRequests.iterator();
			while(iter.hasNext()){
				TokenCertificateRequestWS next = iter.next();

				int certificateProfileId = certificateProfileSession.getCertificateProfileId(next.getCertificateProfileName());
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
				
				CAInfo cAInfo = caSession.getCAInfo(admin, next.getCAName());
				if(cAInfo == null){
					throw EjbcaWSHelper.getEjbcaException("Error the given CA : " + next.getCAName() + " couldn't be found.",
						logger, ErrorCode.CA_NOT_EXISTS, null);
				}

				if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + cAInfo.getCAId())) {
                	final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() + cAInfo.getCAId(), null);
                	throw new AuthorizationDeniedException(msg);
				}
				if(next.getType() == HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST){						
					userData.setCertificateProfileId(certificateProfileId);
					userData.setCAId(cAInfo.getCAId());
					userData.setPassword(password);
					userData.setStatus(EndEntityConstants.STATUS_NEW);
					endEntityManagementSession.changeUser(admin, userData, false);
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
						userData.setStatus(EndEntityConstants.STATUS_NEW);
						endEntityManagementSession.changeUser(admin, userData, true);
						X509Certificate cert;
                        if(eDate == null){
                            cert =  (X509Certificate) signSession.createCertificate(admin,userData.getUsername(),password, keys.getPublic());
                        }else{
                            cert =  (X509Certificate) signSession.createCertificate(admin,userData.getUsername(),password, keys.getPublic(), -1, bDate, eDate);
                        }
						
						genCertificates.add(cert);      
						// Generate Keystore
						// Fetch CA Cert Chain.	        
						Collection<java.security.cert.Certificate> chain =  caSession.getCAInfo(admin, cAInfo.getCAId()).getCertificateChain();
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
            endEntityManagementSession.setUserStatus(admin, userDataWS.getUsername(), EndEntityConstants.STATUS_GENERATED);
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
        } catch (FinderException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return retval; 	
	}
	
    @Override
	public boolean existsHardToken(String hardTokenSN) throws EjbcaException{
		final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			return hardTokenSession.existsHardToken(hardTokenSN);
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
    public HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
            throws CADoesntExistsException, AuthorizationDeniedException, HardTokenDoesntExistsException, NotFoundException,
            ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException, EjbcaException {
		HardTokenDataWS retval = null;
        EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession,
                certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession,
                webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin(true);
		ApprovalRequest ar = null;
		boolean isApprovedStep0 = false;
		boolean isRejectedStep0 = false;

		HardTokenInformation hardTokenData = null;
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
                
                boolean approveViewHardToken = false; // will cause AuthorizationDeniedException
                boolean approveGenTokeCert = false;
                final String approvalProfileIdString = WebServiceConfiguration.getApprovalProfile();   
                ApprovalProfile approvalProfile = null;
                if(StringUtils.isNotEmpty(approvalProfileIdString) && NumberUtils.isNumber(approvalProfileIdString)) {
                    Integer approvalProfileId = Integer.valueOf(approvalProfileIdString);
                    approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileId);
                }
                if(approvalProfile!=null) {
                // TODO: FIX ME!
                    //    approveViewHardToken = arrayContainsValue(approvalProfile.getActionsRequireApproval(), ApprovalRequest.REQ_APPROVAL_VIEW_HARD_TOKEN);
                //    approveGenTokeCert = arrayContainsValue(approvalProfile.getActionsRequireApproval(), ApprovalRequest.REQ_APPROVAL_GENERATE_TOKEN_CERTIFICATE);
                }
                
                if(approveViewHardToken){
                    if (log.isDebugEnabled()) {
                        log.debug("Checking for approvals for getHardTokenData("+hardTokenSN+")");
                    }
                    // Check Approvals
                    // Exists an GenTokenCertificates
                    AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EJBCAWS.getHardTokenData"));
                    EndEntityInformation userData = endEntityAccessSession.findUser(intAdmin, hardTokenData.getUsername());
                    if (userData == null) {
                        log.info(intres.getLocalizedMessage("ra.errorentitynotexist", hardTokenData.getUsername()));
                        String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");            	
                        throw new NotFoundException(msg);
                    }
                    int caid = userData.getCAId();
                    caSession.verifyExistenceOfCA(caid);
                    ar = new GenerateTokenApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenData.getHardToken().getLabel(),
                            admin,null,caid,userData.getEndEntityProfileId(), approvalProfile);
                    int status = ApprovalDataVO.STATUS_REJECTED;
                    try{
                        if(!approveGenTokeCert){
                            throw new ApprovalException("");
                        }
                        status = approvalSession.isApproved(admin, ar.generateApprovalId(), 0);
                        isApprovedStep0 =  status == ApprovalDataVO.STATUS_APPROVED;

                        if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
                                || status == ApprovalDataVO.STATUS_EXPIRED
                                || status == ApprovalDataVO.STATUS_REJECTED){
                            throw new ApprovalException("");
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("A GenerateTokenApprovalRequest exists for "+userData.getUsername()+", "+ar.generateApprovalId());
                        }
                    }catch(ApprovalException e2){
                        if (log.isTraceEnabled()) {
                            log.trace("GenTokenCertificates approval does not exist, try a getHardTokenData request");
                        }
                        if(!approveViewHardToken){
                            throw new AuthorizationDeniedException("EjbcaWS is not configured for getHardTokenData approvals.");
                        }
                        //TODO HANDLE 100% UPTIME HERE
                        ar = new ViewHardTokenDataApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenSN, true,admin,null,
                                0,userData.getCAId(),userData.getEndEntityProfileId(), approvalProfile, null);
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
                        if (log.isDebugEnabled()) {
                            log.debug("Will generate a ViewHardTokenDataApprovalRequest for "+userData.getUsername()+", "+ar.generateApprovalId());
                        }
                        if(genNewRequest){
                            if (log.isDebugEnabled()) {
                                log.debug("Adding an approval request for "+userData.getUsername());
                            }
                            //	Add approval Request
                            try{
                                approvalSession.addApprovalRequest(admin, ar);
                                throw new WaitingForApprovalException("Adding approval to view hard token data with id " + ar.generateApprovalId(), ar.generateApprovalId());
                            }catch(ApprovalException e4){
                                throw EjbcaWSHelper.getEjbcaException(e4, logger, ErrorCode.APPROVAL_ALREADY_EXISTS, null);
                            }
                        }
                    }		
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Not generating any approval request for: "+hardTokenSN);
                    }
                    throw e;
                }
            }

            if(ar != null && isRejectedStep0){
                throw new ApprovalRequestExecutionException("The approval for id " + ar.generateApprovalId() + " have been rejected.");
            }

            if(ar != null && ! isApprovedStep0){
                throw new WaitingForApprovalException("The approval for id " + ar.generateApprovalId() + " have not yet been approved", ar.generateApprovalId());
            }

            Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(hardTokenSN);

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
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return retval;
	}
	
    @Override
	public List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        final AuthenticationToken admin = ejbhelper.getAdmin();
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
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}
    
    private boolean arrayContainsValue(final int[] array, final int value) {
        for(int v : array) {
            if(v==value) {
                return true;
            }
        }
        return false;
    }
	
	private List<HardTokenDataWS> getHardTokenDatas(AuthenticationToken admin, String username, boolean viewPUKData, boolean onlyValidCertificates, IPatternLogger logger)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		List<HardTokenDataWS> retval = new  ArrayList<HardTokenDataWS>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);

		try {
			ejbhelper.isAuthorizedToHardTokenData(admin, username, viewPUKData);

			Collection<HardTokenInformation> hardtokens = hardTokenSession.getHardTokens(admin, username, viewPUKData);
			Iterator<HardTokenInformation> iter = hardtokens.iterator();
			while(iter.hasNext()){
				HardTokenInformation next = (HardTokenInformation) iter.next();
				int caid = next.getSignificantIssuerDN().hashCode();
				caSession.verifyExistenceOfCA(caid);
				if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
                	final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() + caid, null);
                	throw new AuthorizationDeniedException(msg);
				}
				Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(next.getTokenSN());
				if(onlyValidCertificates){
					certs = ejbhelper.returnOnlyValidCertificates(admin, certs);
				}
				retval.add(ejbhelper.convertHardTokenToWS(next,certs, viewPUKData));
			}
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
		} 
		return retval;
	}

    @Override
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException, PublisherException, EjbcaException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try{
			String bcIssuerDN = CertTools.stringToBCDNString(issuerDN);
			caSession.verifyExistenceOfCA(bcIssuerDN.hashCode());
			CertReqHistory certreqhist = certreqHistorySession.retrieveCertReqHistory(new BigInteger(serialNumberInHex,16), bcIssuerDN);
			if(certreqhist == null){
				throw new PublisherException("Error: the  certificate with  serialnumber : " + serialNumberInHex +" and issuerdn " + issuerDN + " couldn't be found in database.");
			}

			ejbhelper.isAuthorizedToRepublish(admin, certreqhist.getUsername(),bcIssuerDN.hashCode());

			if (certreqhist != null) {
				final CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(certreqhist.getEndEntityInformation().getCertificateProfileId());
				if (certprofile != null) {
					if (certprofile.getPublisherList().size() > 0) {
						if (publisherSession.storeCertificate(admin, certprofile.getPublisherList(), certreqhist.getFingerprint(),
						        certreqhist.getEndEntityInformation().getPassword(), certreqhist.getEndEntityInformation().getCertificateDN(), certreqhist.getEndEntityInformation().getExtendedinformation())) {
						} else {
							throw new PublisherException("Error: publication failed to at least one of the defined publishers.");
						}
					} else {
						throw new PublisherException("Error no publisher defined for the given certificate.");
					}
				} else {
					throw new PublisherException("Error : Certificate profile couldn't be found for the given certificate.");
				}	  
			}
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try{
	        // Check authorization to perform custom logging
			if(!authorizationSession.isAuthorized(admin, AuditLogRules.LOG_CUSTOM.resource())) {
            	final String authmsg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AuditLogRules.LOG_CUSTOM.resource(), null);
            	throw new AuthorizationDeniedException(authmsg);
			}

			EventType event = EjbcaEventTypes.CUSTOMLOG_ERROR;
			switch (level) {
			case IEjbcaWS.CUSTOMLOG_LEVEL_ERROR:
				break;
			case IEjbcaWS.CUSTOMLOG_LEVEL_INFO:
				event = EjbcaEventTypes.CUSTOMLOG_INFO;
				break;
			default:
				throw EjbcaWSHelper.getEjbcaException("Illegal level "+ level + " sent to customLog call.", logger, ErrorCode.INVALID_LOG_LEVEL, null);
			}

			java.security.cert.Certificate logCert = null;
			if(certificate != null){
				logCert = CertificateHelper.getCertificate(certificate.getCertificateData());
			}

			int caId = 0;
			if(cAName  != null){
				CAInfo cAInfo = caSession.getCAInfo(admin, cAName);
				caId = cAInfo.getCAId();
			} else {
				caId = ((X509CertificateAuthenticationToken)admin).getCertificate().getSubjectDN().getName().hashCode();
			}

			String comment = type + " : " + msg;
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", comment);
            String certstring = null;
            if (logCert != null) {
            	certstring = CertTools.getSerialNumberAsString(logCert);
            }
            auditSession.log(event, EventStatus.SUCCESS, EjbcaModuleTypes.CUSTOM, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caId), username, certstring, details);
			//logSession.log(admin, caId, LogConstants.MODULE_CUSTOM, new Date(), username, (X509Certificate) logCert, event, comment);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException {
		boolean ret = false;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {

			AuthenticationToken admin = ejbhelper.getAdmin();
            logAdminName(admin,logger);
			ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();
			Iterator<String> iter = userDataSourceNames.iterator();
			while(iter.hasNext()){
				String nextName = iter.next();
				int id = userDataSourceSession.getUserDataSourceId(admin, nextName);
				if(id == 0){
					throw new UserDataSourceException("Error: User Data Source with name : " + nextName + " couldn't be found, aborting operation.");
				}
				userDataSourceIds.add(Integer.valueOf(id));
			}
			ret = userDataSourceSession.removeUserData(admin, userDataSourceIds, searchString, removeMultipleMatch);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }

		return ret; 
	}
	
    @Override
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
			return approvalSession.isApproved(admin, approvalId);
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public Certificate getCertificate(String certSNinHex, String issuerDN) throws CADoesntExistsException,
		AuthorizationDeniedException, EjbcaException {
		Certificate retval = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin(true);
		String bcString = CertTools.stringToBCDNString(issuerDN);
		int caid = bcString.hashCode();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			caSession.verifyExistenceOfCA(caid);
			final String[] rules = {StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate", StandardRules.CAACCESS.resource() + caid};
			if(!authorizationSession.isAuthorizedNoLogging(admin, rules)) {
            	final String authmsg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", Arrays.toString(rules), null);
            	throw new AuthorizationDeniedException(authmsg);
			}
			java.security.cert.Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, new BigInteger(certSNinHex,16));
			if(cert != null){
				retval = new Certificate(cert);
			}
		} catch (CertificateEncodingException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return retval;
	}

    @Override
	public NameAndId[] getAvailableCAs() throws EjbcaException, AuthorizationDeniedException {
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin(true);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			Collection<Integer> caids = caSession.getAuthorizedCaIds(admin);
			HashMap<Integer, String> map = caSession.getCAIdToNameMap();
			for (Integer id : caids ) {
				String name = (String)map.get(id);
				if (name != null) {
					ret.put(name, id);
				}
			}
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return ejbhelper.convertTreeMapToArray(ret);
	}

    @Override
	public NameAndId[] getAuthorizedEndEntityProfiles()
			throws AuthorizationDeniedException, EjbcaException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();
		TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(admin, AccessRulesConstants.CREATE_END_ENTITY);
			final Map<Integer,String> idtonamemap = endEntityProfileSession.getEndEntityProfileIdToNameMap();			
			for (final Integer id : ids) {
				ret.put(idtonamemap.get(id), id);
			}
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		
		return ejbhelper.convertTreeMapToArray(ret);
	}

    @Override
	public NameAndId[] getAvailableCertificateProfiles(final int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
	    final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final AuthenticationToken admin = ejbhelper.getAdmin();
	    final TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
		    final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(entityProfileId);
			if (profile != null) {				
			    final String value = profile.getValue(EndEntityProfile.AVAILCERTPROFILES,0);
				if (value != null) {
				    final String[] availablecertprofilesId = value.split(EndEntityProfile.SPLITCHAR);				
					for (String id : availablecertprofilesId) {
						int i = Integer.parseInt(id);
						ret.put(certificateProfileSession.getCertificateProfileName(i), i);
					}
				}
			}
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return  ejbhelper.convertTreeMapToArray(ret);
	}

    @Override
	public NameAndId[] getAvailableCAsInProfile(final int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
	    final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    final AuthenticationToken admin = ejbhelper.getAdmin();
	    final TreeMap<String,Integer> ret = new TreeMap<String,Integer>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(entityProfileId);
			if (profile != null) {
			    final Collection<String> cas = profile.getAvailableCAs(); // list of CA ids available in profile
			    final HashMap<Integer,String> map = caSession.getCAIdToNameMap();
				for (String id : cas ) {
					Integer i = Integer.valueOf(id);
					String name = (String)map.get(i);
					if (name != null) {
						ret.put(name, i);
					}
				}				
			}
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return ejbhelper.convertTreeMapToArray(ret);
	}
    
    @Override
    public byte[] getProfile(int profileId, String profileType) throws AuthorizationDeniedException, EjbcaException, UnknownProfileTypeException {
        final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
        final AuthenticationToken admin = ejbhelper.getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        
        UpgradeableDataHashMap profile = null;
        if(StringUtils.equalsIgnoreCase(profileType, "eep")) {
            profile = endEntityProfileSession.getEndEntityProfileNoClone(profileId);
            if(profile == null) {
                throw EjbcaWSHelper.getEjbcaException(new EndEntityProfileNotFoundException("Could not find end entity profile with ID '" + profileId + "' in the database."), 
                                                null, ErrorCode.EE_PROFILE_NOT_EXISTS, null);
            }
        } else if(StringUtils.equalsIgnoreCase(profileType, "cp")) {
            profile = certificateProfileSession.getCertificateProfile(profileId);
            if(profile == null) {
                throw EjbcaWSHelper.getEjbcaException(new CertificateProfileDoesNotExistException("Could not find certificate profile with ID '" + profileId + "' in the database."), 
                        null, ErrorCode.CERT_PROFILE_NOT_EXISTS, null);
            }
        } else {
            throw new UnknownProfileTypeException("Unknown profile type '" + profileType + "'. Recognized types are 'eep' for End Entity Profiles and 'cp' for Certificate Profiles");
        }
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(profile.saveData());
        encoder.close();
        byte[] ba = baos.toByteArray();
        try {
            baos.close();
        } catch (IOException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return ba;
    }
    
	@Override
	public void createCRL(String caname) throws CADoesntExistsException, ApprovalException, EjbcaException, ApprovalRequestExpiredException, CryptoTokenOfflineException, CAOfflineException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
			AuthenticationToken admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
            CAInfo cainfo = caSession.getCAInfo(admin, caname);
            publishingCrlSession.forceCRL(admin, cainfo.getCAId());
            publishingCrlSession.forceDeltaCRL(admin, cainfo.getCAId());
		} catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	@Override
    public byte[] getLatestCRL(final String caname, final boolean deltaCRL) throws CADoesntExistsException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
            AuthenticationToken admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
            CAInfo cainfo = caSession.getCAInfo(admin, caname);
            byte[] ret = crlStoreSession.getLastCRL(cainfo.getSubjectDN(), deltaCRL);
            return ret;
        } catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {  // EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    @Override
	public String getEjbcaVersion() {
		return GlobalConfiguration.EJBCA_VERSION;
	}

    @Override
    public int getPublisherQueueLength(String name) throws EjbcaException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
            final AuthenticationToken admin = ejbhelper.getAdmin(true);
            logAdminName(admin,logger);
            final int id = publisherSession.getPublisherId(name);
            if ( id==0 ) {
                return -4;// no publisher with this name
            }
            return publisherQueueSession.getPendingEntriesCountForPublisher(id);
        } catch (AuthorizationDeniedException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    private void setUserDataVOWS(UserDataVOWS userdata) {
    	userdata.setStatus(UserDataVOWS.STATUS_NEW);
    	if (userdata.getPassword() == null) {
    		final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
			final String pwd = pwdgen.getNewPassword(12, 12);									
    		userdata.setPassword(pwd);
    	}
    	userdata.setClearPwd(false);
    	userdata.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
    }

    @Override
	public CertificateResponse certificateRequest(final UserDataVOWS userdata, final String requestData, final int requestType, final String hardTokenSN, final String responseType)
	throws AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	    	if (log.isDebugEnabled()) {
	    		log.debug("CertReq for user '" + userdata.getUsername() + "'.");
	    	}
	        setUserDataVOWS(userdata);
	    	final EjbcaWSHelper ejbcawshelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    	final AuthenticationToken admin = ejbcawshelper.getAdmin(false);
	    	logAdminName(admin,logger);
            enrichUserDataWithRawSubjectDn(userdata);
	        final EndEntityInformation endEntityInformation = ejbcawshelper.convertUserDataVOWS(admin, userdata);
	        int responseTypeInt = CertificateConstants.CERT_RES_TYPE_CERTIFICATE;
	        if (!responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
		        if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
		        	responseTypeInt = CertificateConstants.CERT_RES_TYPE_PKCS7;
		        }
		        else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
		        	responseTypeInt = CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN;
		        }
		        else{
		        	throw new NoSuchAlgorithmException ("Bad responseType:" + responseType);
		        }
	        }

	        return new CertificateResponse(responseType, certificateRequestSession.processCertReq(admin, endEntityInformation, requestData, requestType, hardTokenSN, responseTypeInt));
        } catch( CADoesntExistsException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw new EjbcaException(t);
        } catch( AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch( NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
		} catch (CertificateExtensionException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
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
		} catch (CesecoreException e) {
			// Will convert the CESecore exception to an EJBCA exception with the same error code
			throw EjbcaWSHelper.getEjbcaException(e, null, e.getErrorCode(), null);
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    /** Add the raw subject DN as requested (used if we allow override from request End Entity Information) */
    private void enrichUserDataWithRawSubjectDn(final UserDataVOWS userdata) {
        if (userdata.getExtendedInformation()==null) {
            userdata.setExtendedInformation(new ArrayList<ExtendedInformationWS>());
        }
        userdata.getExtendedInformation().add(new ExtendedInformationWS(ExtendedInformation.RAWSUBJECTDN, userdata.getSubjectDN()));
    }

    @Override
	public KeyStore softTokenRequest(UserDataVOWS userdata, String hardTokenSN, String keyspec, String keyalg)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("Soft token req for user '" + userdata.getUsername() + "'.");
	        userdata.setStatus(UserDataVOWS.STATUS_NEW);
	        userdata.setClearPwd(true);
	    	final EjbcaWSHelper ejbcawshelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
	    	final AuthenticationToken admin = ejbcawshelper.getAdmin(false);
	    	logAdminName(admin,logger);
            enrichUserDataWithRawSubjectDn(userdata);
	        final EndEntityInformation endEntityInformation = ejbcawshelper.convertUserDataVOWS(admin, userdata);
	        final boolean createJKS = userdata.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_JKS);
	        final byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, endEntityInformation, hardTokenSN, keyspec, keyalg, createJKS);
	        // Convert encoded KeyStore to the proper return type
	        final java.security.KeyStore ks;
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
		} catch (InvalidKeyException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.INVALID_KEY, Level.ERROR);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
		} catch (SignatureException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.SIGNATURE_ERROR, Level.ERROR);
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
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
		} catch (EndEntityExistsException e) {
            throw EjbcaWSHelper.getEjbcaException(e, logger, ErrorCode.USER_ALREADY_EXISTS, Level.INFO);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public List<Certificate> getLastCAChain(String caname)
			throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCAChain: "+caname);
		}
		final List<Certificate> retval = new ArrayList<Certificate>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper(wsContext, authorizationSession, caAdminSession, caSession, certificateProfileSession, certificateStoreSession, endEntityAccessSession, endEntityProfileSession, hardTokenSession, endEntityManagementSession, webAuthenticationSession, cryptoTokenManagementSession);
		AuthenticationToken admin = ejbhelper.getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			CAInfo info = caSession.getCAInfo(admin, caname);
			if (info.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE){
				return retval;
			}
     		Collection<java.security.cert.Certificate> certs = info.getCertificateChain();
			Iterator<java.security.cert.Certificate> iter = certs.iterator();
			while (iter.hasNext()){
				retval.add(new Certificate (iter.next ()));
			}
		} catch (CertificateEncodingException e) {
            throw EjbcaWSHelper.getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ...
            throw EjbcaWSHelper.getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		if (log.isTraceEnabled()) {
			log.trace("<getLastCAChain: "+caname);
		}
		return retval;
	}
}
