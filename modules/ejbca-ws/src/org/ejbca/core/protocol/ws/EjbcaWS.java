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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
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
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebServiceConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionWSBridgeSessionLocal;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
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
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.UnknownProfileTypeException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
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
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.protocol.DateNotValidException;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.KeyValuePair;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;

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
    private WebAuthenticationProviderSessionLocal authenticationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
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
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
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
    private KeyStoreCreateSessionLocal keyStoreCreateSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;
    @EJB
    private EnterpriseEditionWSBridgeSessionLocal enterpriseWSBridgeSession;

	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;

	private static final Logger log = Logger.getLogger(EjbcaWS.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    /** Only intended to check if Peer connected instance is authorized to Web Services at all.*/
    private final AuthenticationToken raWsAuthCheckToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("wsServiceAuthCheck"));

    /**
     * Gets an Admin object for a WS-API administrator authenticated with client certificate SSL.
     * Also checks that the admin, if it exists in EJCBA, have access to /administrator, i.e. really is an administrator.
     * Does not check any other authorization though, other than that it is an administrator.
     * Also checks that the admin certificate is not revoked.
     *
     * If Web Services is disabled globally, an UnsupportedOperationException will be thrown
     *
     * @param wsContext web service context that contains the SSL information
     * @return Admin object based on the SSL client certificate
     */
    private AuthenticationToken getAdmin() throws AuthorizationDeniedException {
          return getAdmin(false);
    }

    /**
     * Gets an AuthenticationToken object for a WS-API administrator authenticated with client certificate SSL.
     * - Checks (through authenticationSession.authenticate) that the certificate is valid
     * - If (WebConfiguration.getRequireAdminCertificateInDatabase) checks (through authenticationSession.authenticate) that the admin certificate is not revoked.
     * - If (allowNonAdmin == false), checks that the admin have access to /administrator, i.e. really is an administrator with the certificate mapped in an admin role.
     * - If (AvailableProtocolsConfiguration.getProtocolStatus('WS') == true), checks if Web Services is enabled globally. Otherwise throws UnsupportedOperationException.
     *   Does not check any other authorization though, other than that it is an administrator.
     *
     * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
     * @return AuthenticationToken object based on the SSL client certificate
     * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins == false and the cert does not belong to an admin
     * @throws UnsupportedOperationException if this instance incoming peer connection denies web services
     */
    private AuthenticationToken getAdmin(final boolean allowNonAdmins) throws AuthorizationDeniedException {
        final MessageContext msgContext = wsContext.getMessageContext();
        final HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
        final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        final boolean isServiceEnabled = ((AvailableProtocolsConfiguration)globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID)).getProtocolStatus(AvailableProtocols.WS.getName());
        // Start with checking if it's enabled, preventing any call back to a CA for example (if using an external RA), if WS is not enabled
        if (!isServiceEnabled) {
            throw new UnsupportedOperationException("Web Services not enabled");
        } else if ((certificates == null) || (certificates[0] == null)) {
            throw new AuthorizationDeniedException("Error no client certificate received used for authentication.");
        } else if (!raMasterApiProxyBean.isAuthorizedNoLogging(raWsAuthCheckToken, AccessRulesConstants.REGULAR_PEERPROTOCOL_WS)) {
            throw new UnsupportedOperationException("Not authorized to Web Services");
        }
        return ejbcaWSHelperSession.getAdmin(allowNonAdmins, certificates[0]);

    }

    /**
     * Method used to check if the admin is an administrator
     * i.e have administrator flag set and access to resource
     * /administrator
     */
    private boolean isAdmin() {
        boolean retval = false;
        try {
            if (getAdmin(false) != null) {
                retval = true;
            }
        } catch (AuthorizationDeniedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Not an admin: ", e);
            }
        }
        return retval;
    }

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

    @Override
	@SuppressWarnings("deprecation")
    public void editUser(final UserDataVOWS userdata)
			throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
            AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            if(!raMasterApiProxyBean.editUserWs(admin, userdata)) {
                //If editUser returned true, then an end entity was found and modified. If not, add that user.
                raMasterApiProxyBean.addUserFromWS(admin, userdata, userdata.isClearPwd());
            }
        } catch (EndEntityProfileValidationException e) {
            log.debug(e.toString());
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw new UserDoesntFullfillEndEntityProfile(e);
        } catch (AuthorizationDeniedException e) {
            final String errorMessage = "AuthorizationDeniedException when editing user "+userdata.getUsername()+": "+e.getMessage();
            log.info(errorMessage);
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorMessage);
            throw e;
        } catch (IllegalNameException | CertificateSerialNumberException | EndEntityExistsException e) {
            throw new EjbcaException(e);
        } catch (NoSuchEndEntityException e) {
            throw getEjbcaException(e, logger, ErrorCode.USER_NOT_FOUND, Level.INFO);
        }  catch (RuntimeException e) {  // ClassCastException, EJBException, ...
            throw getInternalException(e, logger);
        }  finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public List<UserDataVOWS> findUser(UserMatch usermatch) throws AuthorizationDeniedException, IllegalQueryException, EjbcaException, EndEntityProfileNotFoundException {
    	if (log.isDebugEnabled()) {
            log.debug("Find user with match '"+usermatch.getMatchvalue()+"'.");
    	}
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
        	final AuthenticationToken admin = getAdmin();
        	logAdminName(admin,logger);
        	return raMasterApiProxyBean.findUserWS(admin, usermatch, MAXNUMBEROFROWS);
        }  catch (RuntimeException e) {	// ClassCastException, EJBException ...
        	throw getInternalException(e, logger);
        } finally {
        	logger.writeln();
        	logger.flush();
        }
	}

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public List<Certificate> findCerts(String username, boolean onlyValid) throws AuthorizationDeniedException, EjbcaException {
        if (log.isDebugEnabled()) {
            log.debug("Find certs for user '"+username+"'.");
        }
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        final List<Certificate> result = new ArrayList<>(0);
        try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            final long now = System.currentTimeMillis();
            try {
                final Collection<java.security.cert.Certificate> certs = EJBTools.unwrapCertCollection(raMasterApiProxyBean.getCertificatesByUsername(admin, username, onlyValid, now));
                for (java.security.cert.Certificate cert : certs) {
                    result.add(new Certificate( cert));
                }
            } catch (CertificateEncodingException e) { // Should never happen!
                log.info("Certificate found for " + username + " could not be encoded: " + e.getMessage());
            }
        } catch (RuntimeException e) {  // EJBException ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return result;
    }

    @Override
	public List<Certificate> getLastCertChain(String username) throws AuthorizationDeniedException, EjbcaException {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCertChain: "+username);
		}
		final List<Certificate> retval = new ArrayList<>();
		AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
		    for (final CertificateWrapper wrapper : raMasterApiProxyBean.getLastCertChain(admin, username)) {
		        retval.add(new Certificate(wrapper.getCertificate()));
		    }
		} catch (EjbcaException e) {
		    logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
		    throw e;
        } catch (CertificateEncodingException | RuntimeException e) {	// EJBException ...
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw new EjbcaException(e);
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
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.createCryptoToken(getAdmin(), tokenName, tokenType, activationPin, autoActivate,
	                cryptotokenProperties);
	    } catch (AuthorizationDeniedException e) {
	        throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw getInternalException(e, logger);
	    } catch (NoSuchSlotException e) {
	        throw getInternalException(e, TransactionLogger.getPatternLogger());
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void generateCryptoTokenKeys(String cryptoTokenName, String keyPairAlias, String keySpecification)
	        throws AuthorizationDeniedException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.generateCryptoTokenKeys(getAdmin(), cryptoTokenName, keyPairAlias, keySpecification);
	    } catch (AuthorizationDeniedException e) {
	        throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw getInternalException(e, logger);
	    } catch (InvalidKeyException e) {
	        throw getEjbcaException(e, null, ErrorCode.INVALID_KEY, Level.INFO);
	    } catch (InvalidAlgorithmParameterException e) {
	        throw getEjbcaException(e, null, ErrorCode.INVALID_KEY_SPEC, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void createCA(String caname, String cadn, String catype, long validityInDays, String certprofile,
	        String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping,
	        List<KeyValuePair> caProperties) throws EjbcaException, AuthorizationDeniedException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        String encodedValidity = String.valueOf(validityInDays)+"d";
	        enterpriseWSBridgeSession.createCA(getAdmin(), caname, cadn, catype, encodedValidity, certprofile,
	                signAlg, signedByCAId, cryptoTokenName, purposeKeyMapping, caProperties);
	    } catch (AuthorizationDeniedException e) {
	        throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw getInternalException(e, logger);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void addSubjectToRole(String roleName, String caName, String matchWith, String matchType,
	        String matchValue) throws EjbcaException, AuthorizationDeniedException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.addSubjectToRole(getAdmin(), roleName, caName, matchWith, matchType, matchValue);
	    } catch (AuthorizationDeniedException e) {
	        throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw getInternalException(e, logger);
	    } catch (RoleNotFoundException e) {
	        throw getEjbcaException(e, null, ErrorCode.ROLE_DOES_NOT_EXIST, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
	public void removeSubjectFromRole(String roleName, String caName, String matchWith, String matchType,
	        String matchValue) throws EjbcaException, AuthorizationDeniedException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.removeSubjectFromRole(getAdmin(), roleName, caName, matchWith, matchType, matchValue);
	    } catch (AuthorizationDeniedException e) {
	        throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
	    } catch (CesecoreException e) {
	        throw getEjbcaException(e, null, e.getErrorCode(), null);
	    } catch (RuntimeException e) {  // ClassCastException, EJBException ...
	        throw getInternalException(e, logger);
	    } catch (RoleNotFoundException e) {
	        throw getEjbcaException(e, null, ErrorCode.ROLE_DOES_NOT_EXIST, Level.INFO);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

	@Override
    public List<Certificate> getCertificatesByExpirationTime(long days, int maxNumberOfResults) throws EjbcaException {
        final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTime(getAdmin(), days, maxNumberOfResults, 0));
        } catch (AuthorizationDeniedException e1) {
            // No authorization required.
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

	@Override
    public List<Certificate> getCertificatesByExpirationTimeAndIssuer(long days, String issuer, int maxNumberOfResults) throws EjbcaException {
	    final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTimeAndIssuer(getAdmin(), days, issuer, maxNumberOfResults));
        } catch (AuthorizationDeniedException e1) {
            // No authorization required.
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

    @Override
    public List<Certificate> getCertificatesByExpirationTimeAndType(long days, int certificateType, int maxNumberOfResults) throws EjbcaException {
        final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTimeAndType(getAdmin(), days, certificateType, maxNumberOfResults));
        } catch (AuthorizationDeniedException e1) {
            // No authorization required.
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

    @Override
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
            throw getInternalException(e, logger);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

    @Override
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
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	@Override
    @SuppressWarnings("deprecation")
    public List<Certificate> cvcRequest(String username, String password, String cvcreq)
            throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException,
            EjbcaException, CesecoreException, ApprovalException, WaitingForApprovalException, SignRequestException, CertificateExpiredException {
        log.trace(">cvcRequest");
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        // Get and old status that we can remember so we can reset status if this fails in the last step.
        int olduserStatus = EndEntityConstants.STATUS_GENERATED;
        try {
            final List<java.security.cert.Certificate> certificates = EJBTools.unwrapCertCollection(raMasterApiProxyBean.processCardVerifiableCertificateRequest(admin, username, password, cvcreq));
            final List<Certificate> result = convertCertificateCollectionToWsObjects(certificates);
            log.trace("<cvcRequest");
            return result;
        } catch (AuthStatusException e) {
            // Have this first, if processReq throws an EjbcaException we want to reset status
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw getInternalException(e, logger); // was not there before.
        } catch (EjbcaException e) {
            // Have this first, if processReq throws an EjbcaException we want to reset status
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw e;
        } catch (ServiceLocatorException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw getInternalException(e, logger);
        } catch (NoSuchEndEntityException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw getInternalException(e, logger);
        }
        catch (CertificateEncodingException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw getInternalException(e, logger);
        }
//        catch (CertificateException e) {  // ECA-6685 Check exception handling.
//            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
//            throw getInternalException(e, logger);
//        }
        catch (RuntimeException e) {  // EJBException, ...
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, olduserStatus);
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    } // cvcRequest

    @Override
	public byte[] caRenewCertRequest(String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException {
		if (log.isTraceEnabled()) {
			log.trace(">caRenewCertRequest");
		}
		if (log.isDebugEnabled()) {
		    log.debug("Create certificate request for CA "+caname+", regeneratekeys="+regenerateKeys+", usenextkey="+usenextkey+", activatekey="+activatekey+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
		}
		AuthenticationToken admin = getAdmin();
		byte[] ret = null;
		try {
			ret = ejbcaWSHelperSession.caRenewCertRequest(admin, caname, cachain, regenerateKeys, usenextkey, activatekey, keystorepwd);
		} catch (CertPathValidatorException e) {
		    throw getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CryptoTokenOfflineException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CryptoTokenAuthenticationFailedException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, null);
		}
		if (log.isTraceEnabled()) {
			log.trace("<caRenewCertRequest");
		}
		return ret;
	} // caRenewCertRequest

    @Override
	public void importCaCert(String caname, byte[] certbytes) throws AuthorizationDeniedException, CAExistsException, EjbcaException {
	    if (log.isTraceEnabled()) {
            log.trace(">importCaCert");
        }
	    if (log.isDebugEnabled()) {
	        log.debug("Import CA certificate for new CA " + caname);
	    }
        final AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.importCaCert(admin, caname, certbytes);
        } catch (CertificateParsingException e) {
            throw getEjbcaException(e, null, ErrorCode.CERT_COULD_NOT_BE_PARSED, Level.INFO);
        } catch (CertificateImportException e) {
            throw getEjbcaException(e, null, ErrorCode.CERTIFICATE_IMPORT, Level.INFO);
        } catch (Exception e) { // EJBException (RuntimeException) and others ...
            throw getInternalException(e, null);
        }
	    if (log.isTraceEnabled()) {
	          log.trace("<importCaCert");
	    }
    } // importCaCert

    @Override
	public void updateCaCert(String caname, byte[] certbytes) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
	    if (log.isTraceEnabled()) {
            log.trace(">updateCaCert");
        }
	    if (log.isDebugEnabled()) {
            log.debug("Update CA certificate for new CA " + caname);
        }
        try {
            ejbcaWSHelperSession.updateCaCert(getAdmin(), caname, certbytes);
        } catch (CADoesntExistsException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_NOT_EXISTS, Level.INFO);
        } catch (CertificateParsingException e) {
            throw getEjbcaException(e, null, ErrorCode.CERT_COULD_NOT_BE_PARSED, Level.INFO);
        } catch (CertificateImportException e) {
            throw getEjbcaException(e, null, ErrorCode.CERTIFICATE_IMPORT, Level.INFO);
        } catch (Exception e) { // EJBException (RuntimeException) and others ...
            throw getInternalException(e, null);
        }
        if (log.isTraceEnabled()) {
            log.trace("<updateCaCert");
        }
    } // updateCaCert

    @Override
	public void caCertResponse(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException {
		log.trace(">caCertResponse");
		log.info("Import certificate response for CA "+caname+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
		AuthenticationToken admin = getAdmin();
		try {
			ejbcaWSHelperSession.caCertResponse(admin, caname, cert, cachain, keystorepwd, false);
		} catch (CertPathValidatorException e) {
		    throw getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CryptoTokenOfflineException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CryptoTokenAuthenticationFailedException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
		} catch (CertificateException e) {
            throw getInternalException(e, null);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, null);
		}
		log.trace("<caCertResponse");
	} // caCertResponse

    @Override
    public void caCertResponseForRollover(String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CesecoreException {
        log.trace(">caCertResponseWithRollover");
        log.info("Import certificate response with rollover for CA "+caname+", keystorepwd: "+(keystorepwd==null?"null":"hidden"));
        AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.caCertResponse(admin, caname, cert, cachain, keystorepwd, true);
        } catch (CertPathValidatorException e) {
            throw getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
        } catch (CryptoTokenOfflineException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (CertificateException e) {
            throw getInternalException(e, null);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, null);
        }
        log.trace("<caCertResponseWithRollover");
    } // caCertResponse

    @Override
    public void rolloverCACert(String caname) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        log.trace(">rolloverCACert");
        log.info("Rollover to next certificate for CA "+caname);
        AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.rolloverCACert(admin, caname);
        } catch (CryptoTokenOfflineException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, null);
        }
        log.trace("<rolloverCACert");
    } // rolloverCACert

    // XXX this method should be modified
    @Override
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
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    private byte[] processCertReq(final String username, final String password, final String req, final int reqType,
            final String hardTokenSN, final String responseType, final IPatternLogger logger) throws EjbcaException, CesecoreException, CADoesntExistsException, AuthorizationDeniedException {
        byte[] result = null;
        try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            result = raMasterApiProxyBean.processCertificateRequest(admin, username, password, req, reqType, hardTokenSN, responseType);
        } catch (CertificateExtensionException e) {
            throw getInternalException(e, logger);
        } catch (NotFoundException e) {
            throw e;
        } catch (InvalidKeyException e) {
            throw getEjbcaException(e, logger, ErrorCode.INVALID_KEY, Level.ERROR);
        } catch (IllegalKeyException e) {
            // Don't log a bad error for this (user's key length too small)
            throw getEjbcaException(e, logger, ErrorCode.ILLEGAL_KEY, Level.DEBUG);
        } catch (AuthStatusException e) {
            // Don't log a bad error for this (user wrong status)
            throw getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
        } catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
        } catch (SignatureException e) {
            throw getEjbcaException(e, logger, ErrorCode.SIGNATURE_ERROR, Level.ERROR);
        } catch (SignRequestSignatureException e) {
            throw getEjbcaException(e.getMessage(), logger, ErrorCode.BAD_REQUEST_SIGNATURE, Level.ERROR);
        } catch (InvalidKeySpecException e) {
            throw getEjbcaException(e, logger, ErrorCode.INVALID_KEY_SPEC, Level.ERROR);
        } catch (CertificateCreateException e) {
            throw getEjbcaException(e, logger, e.getErrorCode(), Level.ERROR);
        } catch (NoSuchAlgorithmException e) {
            throw getInternalException(e, logger);
        } catch (NoSuchProviderException e) {
            throw getInternalException(e, logger);
        } catch (CertificateException e) {
            throw getInternalException(e, logger);
        } catch (IOException e) {
            throw getInternalException(e, logger);
        } catch (ParseException e) {
            // CVC error
            throw getInternalException(e, logger);
        } catch (ConstructionException e) {
            // CVC error
            throw getInternalException(e, logger);
        } catch (NoSuchFieldException e) {
            // CVC error
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } catch(EjbcaException e) {
            // Log exception with logger not injected into RA master API call.
            throw getEjbcaException(e.getMessage(), logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
        }
        return result;
    }

    @Override
	public KeyStore pkcs12Req(String username, String password, String hardTokenSN, String keyspec, String keyalg)
		throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
		    final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            return new KeyStore(raMasterApiProxyBean.generateOrKeyRecoverToken(admin, username, password, hardTokenSN, keyspec, keyalg), password);
		} catch (ClassCastException e) {
            throw getInternalException(e, logger);
		} catch (EJBException e) {
            throw getInternalException(e, logger);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
        } catch(EjbcaException e) {
            throw getEjbcaException(e.getMessage(), logger, e.getErrorCode(), null);
        } catch (RuntimeException e) {	// EJBException, ...
	            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
		}
	}

	private void revokeCert(CertRevocationDto certRevocationDto, IPatternLogger logger) throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException,
	        ApprovalException, WaitingForApprovalException, AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException, CertificateProfileDoesNotExistException {

		if (log.isDebugEnabled()) {
			log.debug("Revoke cert with serial number '" + certRevocationDto.getCertificateSN() +
			        "' from issuer '" + certRevocationDto.getIssuerDN() +
			        "' with reason '" + certRevocationDto.getReason() + "'.");
		}

		try {
			final AuthenticationToken admin = getAdmin();
			logAdminName(admin, logger);
			// Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
			// that was permanently revoked
			// The method over RA Master API will also check if the CA (issuer DN) is something we handle and throw a CADoesntExistsException if not
			certRevocationDto.setCheckDate(true);
			raMasterApiProxyBean.revokeCertWithMetadata(admin, certRevocationDto);
		} catch (NoSuchEndEntityException e) {
			throw new NotFoundException(e.getMessage());
		} catch (RuntimeException e) {	// EJBException, ClassCastException, ...
			throw getInternalException(e, logger);
		}
	}

	@Override
	public void revokeCert(final String issuerDN, final String certificateSN, final int reason) throws
	CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
		    CertRevocationDto certRevocationDto = new CertRevocationDto(issuerDN, certificateSN, reason);
			try {
            	revokeCert(certRevocationDto, logger);
			} catch (RevokeBackDateNotAllowedForProfileException e) {
				throw new Error("This is should not happen since there is no back dating.",e);
			} catch (CertificateProfileDoesNotExistException e) {
	            throw new IllegalStateException("This should not happen since this method overload does not support certificateProfileId input parameter.",e);
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
		    CertRevocationDto certRevocationDto = new CertRevocationDto(issuerDN, certificateSN, reason);

            final Date date = getValidatedDate(sDate);
            certRevocationDto.setRevocationDate(date);

            revokeCert(certRevocationDto, logger);
		} catch (CertificateProfileDoesNotExistException e) {
            throw new IllegalStateException("This should not happen since this method overload does not support certificateProfileId input parameter.",e);
        } finally {
			logger.writeln();
			logger.flush();
		}
	}

	@Override
    public void revokeCertWithMetadata(final String issuerDN, final String certificateSN, final List<KeyValuePair> metadata)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException, ApprovalException,
                   WaitingForApprovalException, AlreadyRevokedException, RevokeBackDateNotAllowedForProfileException, DateNotValidException, CertificateProfileDoesNotExistException
	{
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();

	    try {
    	    CertRevocationDto certRevocationDto = new CertRevocationDto(issuerDN, certificateSN);
    	    certRevocationDto = parseRevocationMetadata(certRevocationDto, metadata);
            revokeCert(certRevocationDto, logger);

	    } finally {
            logger.writeln();
            logger.flush();
        }
	}

    CertRevocationDto parseRevocationMetadata(CertRevocationDto certRevocationDto, final List<KeyValuePair> metadata) throws DateNotValidException {
        final String REASON_KEY = "reason";
        final String REVOCATION_DATE_KEY = "revocationdate";
        final String CERT_PROFILE_ID_KEY = "certificateprofileid";

        if (metadata != null) {
            for (KeyValuePair keyValuePair : metadata) {
                switch (keyValuePair.getKey().toLowerCase()) {
                    case REASON_KEY:
                        int reason = Integer.parseInt(keyValuePair.getValue());
                        certRevocationDto.setReason(reason);
                        break;
                    case REVOCATION_DATE_KEY:
                        Date date = getValidatedDate(keyValuePair.getValue());
                        certRevocationDto.setRevocationDate(date);
                        break;
                    case CERT_PROFILE_ID_KEY:
                        int certificateProfileId = Integer.parseInt(keyValuePair.getValue());
                        certRevocationDto.setCertificateProfileId(certificateProfileId);
                        break;
                }
            }
        }
        return certRevocationDto;
    }

	private Date getValidatedDate(String sDate) throws DateNotValidException {
	    Date date = null;
	    if (sDate != null) {
            try {
                date = DatatypeConverter.parseDateTime(sDate).getTime();
            } catch (IllegalArgumentException e) {
                throw new DateNotValidException( intres.getLocalizedMessage("ra.bad.date", sDate));
            }
            if (date.after(new Date())) {
                throw new DateNotValidException("Revocation date in the future: '" + sDate + "'.");
            }
	    }
        return date;
	}

    @Override
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			final AuthenticationToken admin = getAdmin();
            logAdminName(admin, logger);
            raMasterApiProxyBean.revokeUser(admin, username, reason, deleteUser);
		} catch (NoSuchEndEntityException e) {
		    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
		    throw new NotFoundException(intres.getLocalizedMessage("ra.wrongusernameorpassword"));
		} catch (CouldNotRemoveEndEntityException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
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
			AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);

            boolean usekeyrecovery =((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            if(!usekeyrecovery){
				throw getEjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.",
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
	            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
		        throw new AuthorizationDeniedException(msg);
            }

			// Do the work, mark user for key recovery
			endEntityManagementSession.prepareForKeyRecovery(admin, userdata.getUsername(), userdata.getEndEntityProfileId(), null);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		log.trace("<keyRecoverNewest");
	}

    @Override
    public void keyRecover(String username, String certSNinHex, String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException,
            NotFoundException, EjbcaException, ApprovalException, WaitingForApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">keyRecover");
        }
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            if (log.isDebugEnabled()) {
                log.debug("KeyRecover for user '" + username + "' on certificate with serialNr: '" + certSNinHex + "'.");
            }
            raMasterApiProxyBean.keyRecoverWS(admin, username, certSNinHex, issuerDN);
        } catch (AuthorizationDeniedException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (NotFoundException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (CADoesntExistsException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (WaitingForApprovalException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (ApprovalException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (EjbcaException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } finally {
            logger.writeln();
            logger.flush();
        }
        if (log.isTraceEnabled()) {
            log.trace("<keyRecover");
        }
    }

    @Override
    public KeyStore keyRecoverEnroll(String username, String certSNinHex, String issuerDN, String password, String hardTokenSN)
            throws AuthorizationDeniedException, EjbcaException, CADoesntExistsException, WaitingForApprovalException, NotFoundException {
        if (log.isTraceEnabled()) {
            log.trace(">keyRecoverEnroll");
        }

        // Keystore type is available in UserData but we do it this way to avoid another network round trip, looking it up.
        final byte PKCS12_MAGIC = (byte)48;
        final byte JKS_MAGIC = (byte)(0xfe);

        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);

        try {
            byte[] keyStoreBytes = raMasterApiProxyBean.keyRecoverEnrollWS(admin, username, certSNinHex, issuerDN, password, hardTokenSN);
            final java.security.KeyStore ks;
            final KeyStore keyStore;
            if (keyStoreBytes[0] == PKCS12_MAGIC) {
                ks = java.security.KeyStore.getInstance("PKCS12", "BC");
            } else if (keyStoreBytes[0] == JKS_MAGIC) {
                ks = java.security.KeyStore.getInstance("JKS");
            } else {
                throw new IOException("Unsupported keystore type. Must be PKCS12 or JKS");
            }

            ks.load(new ByteArrayInputStream(keyStoreBytes), password.toCharArray());
            keyStore = new KeyStore(ks, password);
            return keyStore;
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw new EjbcaException(ErrorCode.NOT_SUPPORTED_KEY_STORE, e.getMessage());
        } catch (AuthorizationDeniedException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (CADoesntExistsException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (WaitingForApprovalException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch (NotFoundException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } catch(EjbcaException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    @Override
	public void revokeToken(String hardTokenSN, int reason)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException, EjbcaException, ApprovalException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            revokeToken(getAdmin(), hardTokenSN, reason, logger);
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
            throw getInternalException(e, logger);
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
		            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() +caid, null);
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
            throw getEjbcaException(e.getMessage(), logger, ErrorCode.CERT_WRONG_STATUS, null);
		} catch (NoSuchEndEntityException e) {
			throw new NotFoundException(e.getMessage());
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
		}
	}

    @Override
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();

		try{
		  AuthenticationToken admin = getAdmin();
          logAdminName(admin,logger);
          // The method over RA Master API will also check if the CA (issuer DN) is something we handle and throw a CADoesntExistsException if not
		  // It also checks if we are authorized to the CA, and throws AuthorizationDeniedException if not
          CertificateStatus certinfo = raMasterApiProxyBean.getCertificateStatus(admin, issuerDN, new BigInteger(certificateSN,16));
		  // If certificate is not available, pass this and return null
		  if(certinfo != null && !certinfo.equals(CertificateStatus.NOT_AVAILABLE)){
		    return new RevokeStatus(certinfo, issuerDN, certificateSN);
		  }
		  return null;
        } catch (DatatypeConfigurationException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public boolean isAuthorized(String resource) throws EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
			return raMasterApiProxyBean.isAuthorized(admin, resource);
		} catch (AuthorizationDeniedException ade) {
            return false;
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws UserDataSourceException, EjbcaException, AuthorizationDeniedException{
		final AuthenticationToken admin;
		if(WebServiceConfiguration.getNoAuthorizationOnFetchUserData()){
			final AuthenticationToken tmp = getAdmin(true);
			// We know client certificate is needed, so no other authentication tokens can exist
			X509Certificate admincert = ((X509CertificateAuthenticationToken)tmp).getCertificate();
			admin = new AlwaysAllowLocalAuthenticationToken(admincert.getSubjectDN().getName());
		}else{
			admin = getAdmin();
		}

		final ArrayList<UserDataSourceVOWS> retval = new ArrayList<>();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
			final ArrayList<Integer> userDataSourceIds = new ArrayList<>();
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
			        retval.add(new UserDataSourceVOWS(ejbcaWSHelperSession.convertEndEntityInformation(next.getEndEntityInformation()),next.getIsFieldModifyableSet()));
			    }
			}
        } catch (CADoesntExistsException e) {	// EJBException, ClassCastException, ...
            throw getEjbcaException(e, logger, ErrorCode.CA_NOT_EXISTS, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return retval;
	}

    @SuppressWarnings("deprecation")
    @Override
    public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userDataWS, List<TokenCertificateRequestWS> tokenRequests,
            HardTokenDataWS hardTokenDataWS, boolean overwriteExistingSN, boolean revokePreviousCards) throws CADoesntExistsException,
            AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, EjbcaException, ApprovalRequestExpiredException, ApprovalRequestExecutionException {
    	final ArrayList<TokenCertificateResponseWS> retval = new ArrayList<>();
		AuthenticationToken admin = getAdmin(true);
		int endEntityProfileId = 0;
		boolean hardTokenExists = false;
		boolean userExists = false;

		boolean approvalSuccessfullStep1 = false;
		boolean isRejectedStep1 = false;

		// Get Significant user Id
		final CAInfo significantcAInfo;
		final ArrayList<java.security.cert.Certificate> genCertificates = new ArrayList<>();
		final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		final AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EJBCAWS.genTokenCertificates"));
		try {
			significantcAInfo = caSession.getCAInfo(intAdmin, userDataWS.getCaName());
		if(significantcAInfo == null){
			throw new CADoesntExistsException("Error the given CA : " + userDataWS.getCaName() + " could not be found.");
		}

		EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(intAdmin, userDataWS.getUsername());
		if(endEntityInformation != null){
			endEntityProfileId = endEntityInformation.getEndEntityProfileId();
			userExists = true;
		}else{
		    try {
			endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(userDataWS.getEndEntityProfileName());
		    } catch(EndEntityProfileNotFoundException e) {
		        throw getEjbcaException("Error given end entity profile : " + userDataWS.getEndEntityProfileName() +" could not be found",
                        logger, ErrorCode.EE_PROFILE_NOT_EXISTS, null);
		    }
		}

		// Approval request if we require approvals to generate token certificates
		ApprovalRequest ar = null;
		if (isAdmin()) {
		    final List<String> rules = new ArrayList<>();
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
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", Arrays.toString(rulesArray), null);
                throw new AuthorizationDeniedException(msg);
            }
		} else {
		    final int approvalProfileID = WebServiceConfiguration.getApprovalProfileId();
            if (log.isDebugEnabled()) {
                log.debug("approvalProfileID: "+approvalProfileID);
            }
            ApprovalProfile approvalProfile = null;
            if(approvalProfileID != -1) {
                approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileID);
            }
		    if (approvalProfile!=null) {
		        if (log.isDebugEnabled()) {
		            log.debug("Using ApprovalProfile: "+approvalProfile.getProfileName());
		        }
		        ar = new GenerateTokenApprovalRequest(userDataWS.getUsername(), userDataWS.getSubjectDN(), hardTokenDataWS.getLabel(), admin,
		                null, significantcAInfo.getCAId(), endEntityProfileId, approvalProfile);
		        int status = ApprovalDataVO.STATUS_REJECTED;
		        int requestId = approvalSession.getIdFromApprovalId(ar.generateApprovalId());
		        try{
		            status = approvalSession.isApproved(ar.generateApprovalId(), GenerateTokenApprovalRequest.STEP_1_GENERATETOKEN);
		            approvalSuccessfullStep1 = (status == ApprovalDataVO.STATUS_APPROVED);
		            isRejectedStep1 = (status == ApprovalDataVO.STATUS_REJECTED);
		            if(status == ApprovalDataVO.STATUS_APPROVED){
		                ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(ar.generateApprovalId());
		                String originalDN = ((GenerateTokenApprovalRequest) approvalDataVO.getApprovalRequest()).getDN();
		                userDataWS.setSubjectDN(originalDN); // replace requested DN with original DN to make sure nothing have changed.
		            } else if (status == ApprovalDataVO.STATUS_REJECTED) {
		                throw new ApprovalRequestExecutionException("The approval with approvalID (hash) " + ar.generateApprovalId() + " and ID " + requestId + " has been rejected.");
		            } else if (status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED || status == ApprovalDataVO.STATUS_EXPIRED) {
		                throw new ApprovalException("The approval with approvalID (hash) " + ar.generateApprovalId() + " and ID " + requestId + " has expired.");
		            } else {
		                throw new WaitingForApprovalException("The approval with approvalID (hash) " + ar.generateApprovalId() + " and ID " + requestId + " has not yet been approved", requestId);
		            }
		        } catch (ApprovalException e) {
		            // Request didn't exist
		            requestId = approvalSession.addApprovalRequest(admin, ar);
		            throw new WaitingForApprovalException("Approval request with approvalID (hash) " + ar.generateApprovalId() + " and ID " + requestId + " has been added for approval.", requestId);
		        }
			} else {
			    final String msg = "Can not find an ApprovalProfile with ID: "+approvalProfileID;
			    if (log.isDebugEnabled()) {
			        log.debug(msg);
			    }
				throw new AuthorizationDeniedException(msg);
			}
		}

		if (ar != null && isRejectedStep1) {
		    throw new ApprovalRequestExecutionException("The approval for approvalID (hash) " + ar.generateApprovalId() + " has been rejected.");
		}

		if (ar != null && !approvalSuccessfullStep1) {
		    final int requestId = approvalSession.getIdFromApprovalId(ar.generateApprovalId());
		    throw new WaitingForApprovalException("The approval for ID " + requestId + " has not yet been approved", requestId);
		}
        if (log.isDebugEnabled() && ar != null && approvalSuccessfullStep1) {
            log.debug("The approval for approvalID (hash) " + ar.generateApprovalId() + " has been approved");
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
						} catch (NoSuchEndEntityException e) {
                            throw getEjbcaException("Error revoking old certificate, the user : " + currentHardToken.getUsername() + " of the old certificate couldn't be found in database.",
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
									} catch (NoSuchEndEntityException e) {
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
			EndEntityInformation userData = ejbcaWSHelperSession.convertUserDataVOWS(admin, userDataWS);
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
                    getEjbcaException("Error the given Certificate Profile : " + next.getCertificateProfileName() + " couldn't be found.",
                                      logger, ErrorCode.CERT_PROFILE_NOT_EXISTS, null);
				}

				Date eDate = null;

				if(next.getValidityIdDays() != null ){
					try{
						long validity = Long.parseLong(next.getValidityIdDays());
						eDate = new Date(System.currentTimeMillis() + (validity  * 3600 *24 * 1000));
					}catch (NumberFormatException e){
                        getEjbcaException("Error : Validity in Days must be a number",
                                          logger, ErrorCode.BAD_VALIDITY_FORMAT, null);
					}
				}

				CAInfo cAInfo = caSession.getCAInfo(admin, next.getCAName());
				if(cAInfo == null){
					throw getEjbcaException("Error the given CA : " + next.getCAName() + " couldn't be found.",
						logger, ErrorCode.CA_NOT_EXISTS, null);
				}

				if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + cAInfo.getCAId())) {
                	final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + cAInfo.getCAId(), null);
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
							throw getEjbcaException("Unsupported Key Store Type : " + next.getTokenType() + " only " + HardTokenConstants.TOKENTYPE_PKCS12 + " is supported",
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
						CAInfo info = caSession.getCAInfo(admin, cAInfo.getCAId());
						if (info == null) {
                            throw new CADoesntExistsException("CA with id " + cAInfo.getCAId() + " doesn't exist.");
                        }
						// Fetch CA Cert Chain.
						Collection<java.security.cert.Certificate> chain =  info.getCertificateChain();
						String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
						if (alias == null){
							alias = userData.getUsername();
						}
						java.security.KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

						retval.add(new TokenCertificateResponseWS(new KeyStore(pkcs12, userDataWS.getPassword())));
					}else{
						throw getEjbcaException("Error in request, only REQUESTTYPE_PKCS10_REQUEST and REQUESTTYPE_KEYSTORE_REQUEST are supported token requests.",
							logger, ErrorCode.NOT_SUPPORTED_REQUEST_TYPE, null);
					}
			}

        } catch(Exception e){
            throw getInternalException(e, logger);
        } finally{
            endEntityManagementSession.setUserStatus(admin, userDataWS.getUsername(), EndEntityConstants.STATUS_GENERATED);
		}

		// Add hard token data
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
				throw getEjbcaException("Unsupported PIN Type " + pinData.getType(),
					logger, ErrorCode.NOT_SUPPORTED_PIN_TYPE, null);
			}
		}
		
		HardToken hardToken = new EnhancedEIDHardToken(signatureInitialPIN, signaturePUK, basicInitialPIN, basicPUK, false);

		hardToken.setLabel(hardTokenDataWS.getLabel());
			if(overwriteExistingSN){
				if(hardTokenExists){
					try {
						hardTokenSession.removeHardToken(admin, hardTokenDataWS.getHardTokenSN());
					} catch (HardTokenDoesntExistsException e) {
						throw getEjbcaException(e, logger, ErrorCode.HARD_TOKEN_NOT_EXISTS, Level.ERROR);
					}
				}
			}
			hardTokenSession.addHardToken(admin, hardTokenDataWS.getHardTokenSN(), userDataWS.getUsername(), significantcAInfo.getSubjectDN(), hardToken, genCertificates, hardTokenDataWS.getCopyOfSN());

			if (ar!= null) {
			    // TODO: Don't really understand what this does, but it marks this generate option as "partly done" somehow
			    // after a call to genTokenCertificates this affect a follow up call to getHardTokenData
				approvalSession.markAsStepDone(ar.generateApprovalId(), GenerateTokenApprovalRequest.STEP_1_GENERATETOKEN);
			}
        } catch (NoSuchEndEntityException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return retval;
	}

    @Override
    public boolean existsHardToken(String hardTokenSN) throws EjbcaException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            return hardTokenSession.existsHardToken(hardTokenSN);
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {  // EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @SuppressWarnings("deprecation")
    @Override
    public HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
            throws CADoesntExistsException, AuthorizationDeniedException, HardTokenDoesntExistsException, NotFoundException,
            ApprovalRequestExpiredException, WaitingForApprovalException, ApprovalRequestExecutionException, EjbcaException {
		HardTokenDataWS retval = null;
		AuthenticationToken admin = getAdmin(true);
		ApprovalRequest approvalRequest = null;
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
                ejbcaWSHelperSession.isAuthorizedToHardTokenData(admin, hardTokenData.getUsername(), viewPUKData);
            }catch(AuthorizationDeniedException e){
                boolean genNewRequest = false;

                final int approvalProfileID = WebServiceConfiguration.getApprovalProfileId();
                if (log.isDebugEnabled()) {
                    log.debug("approvalProfileID: "+approvalProfileID);
                }
                ApprovalProfile approvalProfile = null;
                if(approvalProfileID != -1) {
                    approvalProfile = approvalProfileSession.getApprovalProfile(approvalProfileID);
                }
                if(approvalProfile != null){
                    if (log.isDebugEnabled()) {
                        log.debug("Using Approval Profile with name: "+approvalProfile.getProfileName());
                    }
                    // Check if an approval request for GenTokenCertificates exists, in that case we can not view the hard token data
                    if (log.isDebugEnabled()) {
                        log.debug("Checking for existing Generate approvals for getHardTokenData("+hardTokenSN+")");
                    }
                    AuthenticationToken intAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EJBCAWS.getHardTokenData"));
                    EndEntityInformation userData = endEntityAccessSession.findUser(intAdmin, hardTokenData.getUsername());
                    if (userData == null) {
                        log.info(intres.getLocalizedMessage("ra.errorentitynotexist", hardTokenData.getUsername()));
                        String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
                        throw new NotFoundException(msg);
                    }
                    int caid = userData.getCAId();
                    caSession.verifyExistenceOfCA(caid);
                    approvalRequest = new GenerateTokenApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenData.getHardToken().getLabel(),
                            admin,null,caid,userData.getEndEntityProfileId(), approvalProfile);
                    int status = ApprovalDataVO.STATUS_REJECTED;
                    try {
                        status = approvalSession.isApproved(approvalRequest.generateApprovalId(), GenerateTokenApprovalRequest.STEP_0_VIEWHARDTOKENDATA);
                        isApprovedStep0 =  status == ApprovalDataVO.STATUS_APPROVED;

                        if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
                                || status == ApprovalDataVO.STATUS_EXPIRED
                                || status == ApprovalDataVO.STATUS_REJECTED){
                            throw new ApprovalException("");
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("A GenerateTokenApprovalRequest exists for "+userData.getUsername()+", "+approvalRequest.generateApprovalId()+", we can not get the data yet.");
                        }
                    } catch(ApprovalException e2) {
                        if (log.isDebugEnabled()) {
                            log.debug("A GenerateTokenApprovalRequest does not exist, looking for a View getHardTokenData request: "+e2.getMessage());
                        }
                        approvalRequest = new ViewHardTokenDataApprovalRequest(userData.getUsername(), userData.getDN(), hardTokenSN, true, admin, null, 0,
                                userData.getCAId(), userData.getEndEntityProfileId(), approvalProfile);
                        try{
                            status = approvalSession.isApproved(approvalRequest.generateApprovalId());
                            isApprovedStep0 = status == ApprovalDataVO.STATUS_APPROVED;
                            isRejectedStep0 =  status == ApprovalDataVO.STATUS_REJECTED;
                            if(   status == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED
                                    || status == ApprovalDataVO.STATUS_EXPIRED){
                                genNewRequest = true;
                            }
                        }catch(ApprovalException e3){
                            genNewRequest = true;
                        }catch(ApprovalRequestExpiredException e3){
                            genNewRequest = true;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("Will generate a ViewHardTokenDataApprovalRequest for "+userData.getUsername()+", "+approvalRequest.generateApprovalId());
                        }
                        if (genNewRequest) {
                            if (log.isDebugEnabled()) {
                                log.debug("Adding an approval request for "+userData.getUsername());
                            }
                            //  Add approval Request
                            try{
                                final int requestId = approvalSession.addApprovalRequest(admin, approvalRequest);
                                throw new WaitingForApprovalException("Adding approval request to view hard token data with ID " + requestId, requestId);
                            }catch(ApprovalException e4){
                                throw getEjbcaException(e4, logger, ErrorCode.APPROVAL_ALREADY_EXISTS, null);
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Can not find an ApprovalProfile with ID: "+approvalProfileID+", not generating any approval request for: "+hardTokenSN);
                    }
                    throw e;
                }
            }

            if(approvalRequest != null && isRejectedStep0){
                throw new ApprovalRequestExecutionException("The approval for approvalID (hash) " + approvalRequest.generateApprovalId() + " have been rejected.");
            }

            if(approvalRequest != null && ! isApprovedStep0){
                final int requestId = approvalSession.getIdFromApprovalId(approvalRequest.generateApprovalId());
                throw new WaitingForApprovalException("The approval for ID " + requestId + " has not yet been approved", requestId);
            }

            Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(hardTokenSN);

            if (onlyValidCertificates) {
                certs = ejbcaWSHelperSession.returnOnlyValidCertificates(admin, certs);
            }

            retval = ejbcaWSHelperSession.convertHardTokenToWS(hardTokenData, certs, viewPUKData);

            if(approvalRequest != null){
                try {
                    approvalSession.markAsStepDone(approvalRequest.generateApprovalId(), GenerateTokenApprovalRequest.STEP_0_VIEWHARDTOKENDATA);
                } catch (ApprovalException e) {
                    throw getEjbcaException(e, logger, ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, null);
                }
            }
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return retval;
	}

    @Override
	public List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        final AuthenticationToken admin = getAdmin();
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
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	private List<HardTokenDataWS> getHardTokenDatas(AuthenticationToken admin, String username, boolean viewPUKData, boolean onlyValidCertificates, IPatternLogger logger)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		List<HardTokenDataWS> retval = new ArrayList<>();
		try {
			ejbcaWSHelperSession.isAuthorizedToHardTokenData(admin, username, viewPUKData);

			Collection<HardTokenInformation> hardtokens = hardTokenSession.getHardTokens(admin, username, viewPUKData);
			for (final HardTokenInformation next : hardtokens) {
				int caid = next.getSignificantIssuerDN().hashCode();
				caSession.verifyExistenceOfCA(caid);
				if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
                	final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caid, null);
                	throw new AuthorizationDeniedException(msg);
				}
				Collection<java.security.cert.Certificate> certs = hardTokenSession.findCertificatesInHardToken(next.getTokenSN());
				if(onlyValidCertificates){
					certs = ejbcaWSHelperSession.returnOnlyValidCertificates(admin, certs);
				}
				retval.add(ejbcaWSHelperSession.convertHardTokenToWS(next,certs, viewPUKData));
			}
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
		}
		return retval;
	}

    @Override
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException, PublisherException, EjbcaException{
		final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try{
			raMasterApiProxyBean.republishCertificate(admin, serialNumberInHex, issuerDN);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg)
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        EventType event = EjbcaEventTypes.CUSTOMLOG_ERROR;
        switch (level) {
            case IEjbcaWS.CUSTOMLOG_LEVEL_ERROR:
                break;
            case IEjbcaWS.CUSTOMLOG_LEVEL_INFO:
                event = EjbcaEventTypes.CUSTOMLOG_INFO;
                break;
            default:
                throw getEjbcaException("Illegal level "+ level + " sent to customLog call.", logger, ErrorCode.INVALID_LOG_LEVEL, null);
        }
		try{
			String certificateSn = null;
		    if (certificate != null) {
                final java.security.cert.Certificate logCert = CertificateHelper.getCertificate(certificate.getCertificateData());
                certificateSn = CertTools.getSerialNumberAsString(logCert);
            }
		    raMasterApiProxyBean.customLog(admin, type, cAName, username, certificateSn, msg, event);
		} catch (CertificateException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException {
		boolean ret = false;
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {

			AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
			ArrayList<Integer> userDataSourceIds = new ArrayList<>();
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
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }

		return ret;
	}

    @Override
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            // Local instance is requested in any case; request to RaMasterAPI should never fail.
            return raMasterApiProxyBean.isApproved(admin, approvalId);
		} catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @Override
    public int getRemainingNumberOfApprovals(int requestId) throws ApprovalException, AuthorizationDeniedException, ApprovalRequestExpiredException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin, logger);
            final Integer requestResult = raMasterApiProxyBean.getRemainingNumberOfApprovals(admin, requestId);
            int result;
            if (requestResult != null) {
                result = requestResult;
            } else {
                result = -9;
            }
            return result;
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    @Override
    public Certificate getCertificate(String certSNinHex, String issuerDN) throws CADoesntExistsException,
        AuthorizationDeniedException, EjbcaException {
        Certificate result = null;
        final AuthenticationToken admin = getAdmin(true);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
            final CertificateWrapper certificateWrapper = raMasterApiProxyBean.getCertificate(admin, certSNinHex, issuerDN);
            if(certificateWrapper != null){
                result = new Certificate(certificateWrapper.getCertificate());
            }
        } catch (CertificateEncodingException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return result;
    }

    @Override
	public NameAndId[] getAvailableCAs() throws EjbcaException, AuthorizationDeniedException {
		final TreeMap<String,Integer> result = new TreeMap<>();
		final AuthenticationToken admin = getAdmin(true);
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
			final Collection<CAInfo> cas = raMasterApiProxyBean.getAuthorizedCas(admin);
			for (CAInfo ca: cas) {
				result.put(ca.getName(), ca.getCAId());
			}
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return convertTreeMapToArray(result);
	}

    @Override
    public NameAndId[] getAuthorizedEndEntityProfiles()
            throws AuthorizationDeniedException, EjbcaException {
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        final IdNameHashMap<EndEntityProfile> result = new IdNameHashMap<>();
        try {
            result.putAll(raMasterApiProxyBean.getAuthorizedEndEntityProfiles(admin, AccessRulesConstants.CREATE_END_ENTITY));
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return convertIdNameHashMapToArray(result);
    }

    @Override
    public NameAndId[] getAvailableCertificateProfiles(final int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
        final AuthenticationToken admin = getAdmin();
        final TreeMap<String,Integer> result = new TreeMap<>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
            result.putAll(raMasterApiProxyBean.getAvailableCertificateProfiles(admin, entityProfileId));
        } catch (EndEntityProfileNotFoundException e) {
            // NOOP.
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return convertTreeMapToArray(result);
    }

    @Override
    public NameAndId[] getAvailableCAsInProfile(final int entityProfileId) throws AuthorizationDeniedException, EjbcaException {
        final AuthenticationToken admin = getAdmin();
        final TreeMap<String,Integer> result = new TreeMap<>();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
            result.putAll(raMasterApiProxyBean.getAvailableCasInProfile(admin, entityProfileId));
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } catch (EndEntityProfileNotFoundException e) {
            // NOOP.
        } finally {
            logger.writeln();
            logger.flush();
        }
        return convertTreeMapToArray(result);
    }

    @Override
    public byte[] getProfile(int profileId, String profileType) throws AuthorizationDeniedException, EjbcaException, UnknownProfileTypeException {
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin, logger);
        try {
            if (StringUtils.equalsIgnoreCase(profileType, "eep")) {
                return raMasterApiProxyBean.getEndEntityProfileAsXml(admin, profileId);
            } else if (StringUtils.equalsIgnoreCase(profileType, "cp")) {
                return raMasterApiProxyBean.getCertificateProfileAsXml(admin, profileId);
            } else {
                throw new UnknownProfileTypeException("Unknown profile type '" + profileType
                        + "'. Recognized types are 'eep' for End Entity Profiles and 'cp' for Certificate Profiles");
            }

        } catch (org.ejbca.core.model.ra.UnknownProfileTypeException e) {
            throw new UnknownProfileTypeException(e.getMessage());
        } catch (CertificateProfileDoesNotExistException | EndEntityProfileNotFoundException e) {
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

	@Override
	public void createCRL(String caname) throws CADoesntExistsException, ApprovalException, EjbcaException, ApprovalRequestExpiredException, CryptoTokenOfflineException, CAOfflineException{
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            CAInfo cainfo = caSession.getCAInfo(admin, caname);
            if (cainfo == null) {
                throw new CADoesntExistsException("CA with name " + caname + " doesn't exist.");
            }
            publishingCrlSession.forceCRL(admin, cainfo.getCAId());
            publishingCrlSession.forceDeltaCRL(admin, cainfo.getCAId());
		} catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	@Override
    public byte[] getLatestCRL(final String caname, final boolean deltaCRL) throws CADoesntExistsException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            return raMasterApiProxyBean.getLatestCrl(admin, caname, deltaCRL);
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    @Override
    public byte[] getLatestCRLPartition(String caName, boolean deltaCRL, int crlPartitionIndex) throws CADoesntExistsException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            RaCrlSearchRequest request = new RaCrlSearchRequest();
            request.setCaName(caName);
            request.setCrlPartitionIndex(crlPartitionIndex);
            request.setDeltaCRL(deltaCRL);
            return raMasterApiProxyBean.getLatestCrlByRequest(admin, request);
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
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
    public int getPublisherQueueLength(String name) throws EjbcaException {
        if (log.isDebugEnabled()) {
            log.debug("getPublisherQueueLength for queue '" + name + "'.");
        }
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            return raMasterApiProxyBean.getPublisherQueueLength(admin, name);
        } catch (PublisherDoesntExistsException e) {
            return -4; // error code according to API
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) { // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    private void setUserDataVOWS(UserDataVOWS userdata) {
    	userdata.setStatus(EndEntityConstants.STATUS_NEW);
    	if (userdata.getPassword() == null) {
    		final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
			final String pwd = pwdgen.getNewPassword(12, 12);
    		userdata.setPassword(pwd);
    	}
    	userdata.setClearPwd(false);
    	userdata.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
    }

    @SuppressWarnings("deprecation")
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
	    	final AuthenticationToken admin = getAdmin(false);
	    	logAdminName(admin,logger);
	        return new CertificateResponse(responseType, raMasterApiProxyBean.createCertificateWS(admin, userdata, requestData, requestType,
	                hardTokenSN, responseType));
	    } catch( AuthorizationDeniedException t ) {
	        logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
	        throw t;
	    } catch( NotFoundException t ) {
	        logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
	        throw t;
	    } catch (EjbcaException e) {
	        Level loglevel = Level.DEBUG;
	        if (e.getErrorCode() != null) {
    	        final String err = e.getErrorCode().getInternalErrorCode();
    	        logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.getErrorCode().toString());
    	        // Don't log at ERROR log level for the following cases (for example):
                //   - user's key length too small (ILLEGAL_KEY)
                //   - wrong user status (USER_WRONG_STATUS)
                //   - other EjbcaExceptions and CESeCoreExceptions
    	        if (ErrorCode.INTERNAL_ERROR.getInternalErrorCode().equals(err) ||
    	                ErrorCode.SIGNATURE_ERROR.getInternalErrorCode().equals(err) ||
    	                ErrorCode.INVALID_KEY.getInternalErrorCode().equals(err) ||
    	                ErrorCode.LOGIN_ERROR.getInternalErrorCode().equals(err) ||
    	                ErrorCode.INVALID_KEY_SPEC.getInternalErrorCode().equals(err)) {
    	            loglevel = Level.ERROR;
    	        }
	        }
	        log.log(loglevel, "EJBCA WebService error", e);
	        throw e;
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ... (if related to the RA connection, or if not caught by the RA)
            log.error("EJBCA WebService error", e);
            throw new EjbcaException(e);
        } catch (EndEntityProfileValidationException e) {
           throw new UserDoesntFullfillEndEntityProfile(e);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    @SuppressWarnings("deprecation")
    @Override
	public KeyStore softTokenRequest(UserDataVOWS userdata, String hardTokenSN, String keyspec, String keyalg)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
	ApprovalException, WaitingForApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("Soft token req for user '" + userdata.getUsername() + "'.");
	        userdata.setStatus(EndEntityConstants.STATUS_NEW);
	        userdata.setClearPwd(true);
	    	final AuthenticationToken admin = getAdmin(false);
	    	logAdminName(admin,logger);
	        final EndEntityInformation endEntityInformation = ejbcaWSHelperSession.convertUserDataVOWS(admin, userdata);
	        final boolean createJKS = userdata.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_JKS);
	        final byte[] encodedKeyStore = certificateRequestSession.processSoftTokenReq(admin, endEntityInformation, hardTokenSN, keyspec, keyalg, createJKS);
	        // Convert encoded KeyStore to the proper return type
	        final java.security.KeyStore ks;
	        if (createJKS) {
	        	ks = java.security.KeyStore.getInstance("JKS");
	        } else {
	            // BC PKCS12 uses 3DES for key protection and 40 bit RC2 for protecting the certificates
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
        } catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.ERROR);
		} catch (NoSuchEndEntityException e) {
            throw getEjbcaException(e, logger, ErrorCode.USER_NOT_FOUND, Level.INFO);
        }catch (NoSuchAlgorithmException e) {
            throw getInternalException(e, logger);
		} catch (NoSuchProviderException e) {
            throw getInternalException(e, logger);
        } catch( KeyStoreException e ) {
            throw getInternalException(e, logger);
		} catch (CertificateException e) {
            throw getInternalException(e, logger);
		} catch (IOException e) {
            throw getInternalException(e, logger);
		}  catch (EndEntityExistsException e) {
            throw getEjbcaException(e, logger, ErrorCode.USER_ALREADY_EXISTS, Level.INFO);
        } catch (CertificateSerialNumberException e) {
            throw getInternalException(e, logger);
        } catch (IllegalNameException e) {
            throw getInternalException(e, logger);
        } catch (InvalidKeySpecException e) {
            throw getInternalException(e, logger);
        } catch (InvalidAlgorithmParameterException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } catch (EndEntityProfileValidationException e) {
            throw new UserDoesntFullfillEndEntityProfile(e);
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
        final List<Certificate> result = new ArrayList<>();
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
            final Collection<CertificateWrapper> certificates = raMasterApiProxyBean.getLastCaChain(admin, caname);
            for (final CertificateWrapper certWrapper : certificates) {
                result.add(new Certificate(certWrapper.getCertificate()));
            }
        } catch (CertificateEncodingException e) {
            throw getInternalException(e, logger);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getLastCAChain: "+caname);
        }
        return result;
    }

    private static EjbcaException getInternalException(Throwable t, IPatternLogger logger) {
        return getEjbcaException( t, logger, ErrorCode.INTERNAL_ERROR, Level.ERROR);
    }

    private static EjbcaException getEjbcaException(final Throwable t, final IPatternLogger logger, final ErrorCode errorCode, final Level level) {
        if (level !=null ) {
            log.log(level, "EJBCA WebService error", t);
        }
        if (logger != null) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorCode.toString());
        }
        return new EjbcaException(errorCode, t.getMessage());
    }

    private static EjbcaException getEjbcaException(final String s, final IPatternLogger logger, final ErrorCode errorCode, final Level level) {
        if (level !=null) {
            log.log(level, s);
        }
        if (logger != null) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), s);
        }
        if ( errorCode!=null ) {
            if (logger != null) {
                logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorCode.toString());
            }
            return new EjbcaException(errorCode, s);
        }
        return new EjbcaException(s);
    }

    private static ArrayList<Certificate> unwrapCertificatesOrThrowInternalException(Collection<CertificateWrapper> certificates) throws EjbcaException {
        final ArrayList<Certificate> result = new ArrayList<>();
        for (CertificateWrapper certificate : certificates) {
            try {
                result.add(new Certificate(certificate.getCertificate()));
            } catch (CertificateEncodingException e) {
                throw getInternalException(e, TransactionLogger.getPatternLogger());
            }
        }
        return result;
    }

    /**
     * Creates a NameAndId array by the given map of name / ID pairs.
     *
     * @param map the map of name / ID pairs.
     * @return an array of NameAndId objects in the same order as in the map.
     */
    private static NameAndId[] convertTreeMapToArray(final Map<String, Integer> map) {
        NameAndId[] result;
        if ((map == null) || (map.size() == 0)) {
            result = new NameAndId[0];
        } else {
            result = new NameAndId[map.size()];
            int i = 0;
            for (String name : map.keySet()) {
                result[i++] = new NameAndId(name, map.get(name));
            }
        }
        return result;
    }

    /**
     * Creates a NameAndId array by the given map of name / ID pairs.
     *
     * @param map the map of name / ID pairs.
     * @return an array of NameAndId objects in the same order as in the map.
     */
    private static NameAndId[] convertIdNameHashMapToArray(final IdNameHashMap<?> map) {
        NameAndId[] result;
        if ((map == null) || (map.size() == 0)) {
            result = new NameAndId[0];
        } else {
            result = new NameAndId[map.size()];
            int i = 0;
            for (String name : map.nameKeySet()) {
                result[i++] = new NameAndId(name, map.get(name).getId());
            }
        }
        return result;
    }
    
    private static List<Certificate> convertCertificateCollectionToWsObjects(List<java.security.cert.Certificate> certificates) throws CertificateEncodingException {
        final List<Certificate> result = new ArrayList<>();
        for (java.security.cert.Certificate certificate : certificates) {
            result.add(new Certificate(certificate));
        }
        return result;
    }
}
