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
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.ws.Action;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.roles.RoleNotFoundException;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebServiceConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.EnterpriseEditionWSBridgeSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaCrlSearchRequest;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
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
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.logger.TransactionLogger;
import org.ejbca.core.protocol.ws.logger.TransactionTags;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.CertificateResponse;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.SshRequestMessageWs;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.protocol.DateNotValidException;
import org.ejbca.util.HttpTools;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.KeyValuePair;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.CertificateWrapper;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Implementor of the IEjbcaWS interface.
 * Keep this class free of other helper methods, and implement them in the helper classes instead.
 * <p>The WebService name below is important because it determines the webservice URL on JBoss 7.1.</p>
 * <p>Do not ever remove (or change) a method in the web service interface, it will cause clients
 * built using older versions to break, even if they do not use the removed method.</p>
 */
@Stateless
@WebService(name="EjbcaWS", serviceName="EjbcaWSService", targetNamespace="http://ws.protocol.core.ejbca.org/", portName="EjbcaWSPort")	//portName="EjbcaWSPort" default
public class EjbcaWS implements IEjbcaWS {
	@Resource
	private WebServiceContext wsContext;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateRequestSessionLocal certificateRequestSession;
    @EJB
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;
    @EJB
    private EnterpriseEditionWSBridgeSessionLocal enterpriseWSBridgeSession;

	/** The maximum number of rows returned in array responses. */
	private static final int MAX_NUMBER_OF_ROWS = 100;

	private static final Logger log = Logger.getLogger(EjbcaWS.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    /** Only intended to check if Peer connected instance is authorized to Web Services at all.*/
    private final AuthenticationToken raWsAuthCheckToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("wsServiceAuthCheck"));

    /**
     * Gets an Admin object for a WS-API administrator authenticated with client certificate SSL.
     * Also checks that the admin, if it exists in EJBCA, have access to /administrator, i.e. really is an administrator.
     * Does not check any other authorization though, other than that it is an administrator.
     * Also checks that the admin certificate is not revoked.
     *
     * If Web Services is disabled globally, an UnsupportedOperationException will be thrown
     *
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
        final X509Certificate certificate = certificates != null ? certificates[0] : null;
        final String oauthBearerToken = HttpTools.extractBearerAuthorization(request.getHeader(HttpTools.AUTHORIZATION_HEADER));

        final boolean isServiceEnabled = ((AvailableProtocolsConfiguration)globalConfigurationSession.getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID)).getProtocolStatus(AvailableProtocols.WS.getName());

        // Start with checking if it's enabled, preventing any call back to a CA for example (if using an external RA), if WS is not enabled
        if (!isServiceEnabled) {
            throw new UnsupportedOperationException("Web Services not enabled");
        } else if (certificate == null && StringUtils.isEmpty(oauthBearerToken)) {
            throw new AuthorizationDeniedException("Error no client certificate or OAuth token received used for authentication.");
        } else if (!raMasterApiProxyBean.isAuthorizedNoLogging(raWsAuthCheckToken, AccessRulesConstants.REGULAR_PEERPROTOCOL_WS)) {
            throw new UnsupportedOperationException("Not authorized to Web Services");
        }
        return ejbcaWSHelperSession.getAdmin(allowNonAdmins, certificate, oauthBearerToken);

    }

    private void logAdminName(final AuthenticationToken admin, final IPatternLogger logger) {
        // Log certificate info
        if (admin instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) admin;
            logger.paramPut(TransactionTags.OAUTH_NAME.toString(), token.getClaims().getName());
            logger.paramPut(TransactionTags.OAUTH_ISSUER.toString(), token.getClaims().getIssuer());
        } else {
            final X509Certificate cert = ((X509CertificateAuthenticationToken) admin).getCertificate();
            logger.paramPut(TransactionTags.ADMIN_DN.toString(), cert.getSubjectDN().toString());
            logger.paramPut(TransactionTags.ADMIN_ISSUER_DN.toString(), cert.getIssuerDN().toString());
        }
            // Log IP address
            MessageContext msgCtx = wsContext.getMessageContext();
            HttpServletRequest request = (HttpServletRequest) msgCtx.get(MessageContext.SERVLET_REQUEST);
            logger.paramPut(TransactionTags.ADMIN_REMOTE_IP.toString(), request.getRemoteAddr());
            logger.paramPut(TransactionTags.ADMIN_FORWARDED_IP.toString(), StringTools.getCleanXForwardedFor(request.getHeader("X-Forwarded-For")));
    }

    /**
     * Edits/adds a user to the EJBCA database.
     *
     * If the user doesn't already exists it will be added otherwise it will be
     * overwritten.
     *
     * Observe: if the user doesn't already exists, it's status will always be set to 'New'.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/create_end_entity and/or edit_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * @param userData contains all the information about the user about to be added.
     * clearPwd indicates it the password should be stored in clear text, required
     * when creating server generated keystores.
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws UserDoesntFullfillEndEntityProfile if we add or edit a profile that doesn't match its end entity profile.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/editUser")
	@SuppressWarnings("deprecation")
    public void editUser(final UserDataVOWS userData)
			throws CADoesntExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, EjbcaException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
            AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            if(!raMasterApiProxyBean.editUserWs(admin, userData)) {
                //If editUser returned true, then an end entity was found and modified. If not, add that user.
                raMasterApiProxyBean.addUserFromWS(admin, userData, userData.isClearPwd());
            }
        } catch (EndEntityProfileValidationException e) {
            log.debug(e.toString());
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw new UserDoesntFullfillEndEntityProfile(e);
        } catch (AuthorizationDeniedException e) {
            final String errorMessage = "AuthorizationDeniedException when editing user " + userData.getUsername()+": " + e.getMessage();
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

    /**
     * Retrieves information about users in the database.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of matching users&gt;/view_end_entity
     * - /ca/&lt;ca of usermatch&gt; - when matching on CA
     * </pre>
     *
     * @param usermatch the unique user pattern to search for
     * @return a array of {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS} objects (Max 100) containing the information about the user or null if there are no matches.
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws IllegalQueryException if query isn't valid
     * @throws EjbcaException if an error occurred
     * @throws EndEntityProfileNotFoundException if an end entity profile was not found.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/findUser")
	public List<UserDataVOWS> findUser(UserMatch usermatch)
            throws AuthorizationDeniedException, IllegalQueryException, EjbcaException {
    	if (log.isDebugEnabled()) {
            log.debug("Find user with match '"+usermatch.getMatchvalue()+"'.");
    	}
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
        	final AuthenticationToken admin = getAdmin();
        	logAdminName(admin,logger);
        	return raMasterApiProxyBean.findUserWS(admin, usermatch, MAX_NUMBER_OF_ROWS);
        }  catch (RuntimeException e) {	// ClassCastException, EJBException ...
        	throw getInternalException(e, logger);
        } finally {
        	logger.writeln();
        	logger.flush();
        }
	}

    /**
     * Retrieves a collection of certificates generated for a user.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * <p>If authorization was denied or a certificate could not be encoded on the local system,
     *    then the request will be forwarded to upstream peer systems (if any) and the resulting
     *    certificates where merged by its fingerprint.</p>
     *
     * @param username a unique username
     * @param onlyValid only return valid certs not revoked or expired ones.
     * @return a collection of Certificates or an empty list if no certificates, or no user, could be found
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/findCerts")
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public List<Certificate> findCerts(String username, boolean onlyValid)
            throws AuthorizationDeniedException, EjbcaException {
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

    /**
     * Retrieves the last certificate to expire for a given user. More formally, returns the certificate chain
     * [C1, C2... Cn] where C1 is the user's leaf certificate and Cn is the root certificate, such that it does
     * not exist a leaf certificate for the same user with an expiration date exceeding the expiration date of C1.
     * <p>
     * This method does not check whether the certificate to be returned has been revoked.
     * <p>
     * If the user is not found on the local system, then the query will be forwarded to upstream peer systems (if any).
     * <p>
     * Prior to EJBCA 6.8.0, the documentation incorrectly stated that this method could return null when it actually returns an empty list.
     *
     * <pre>
     * <b>Authorization requirements:</b>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * @param username the unique username of the user whose certificate should be returned
     * @return a list of X509 Certificates with the leaf certificate first, or an empty list if no certificate chain could be found for the specified user
     * @throws AuthorizationDeniedException if the client does not fulfill the authorization requirements specified above
     * @throws EjbcaException on internal errors, such as badly encoded certificate
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getLastCertChain")
	public List<Certificate> getLastCertChain(String username) throws AuthorizationDeniedException, EjbcaException {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCertChain: "+username);
		}
		final List<Certificate> retValues = new ArrayList<>();
		AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
		try {
		    for (final CertificateWrapper wrapper : raMasterApiProxyBean.getLastCertChain(admin, username)) {
		        retValues.add(new Certificate(wrapper.getCertificate()));
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
		return retValues;
	}

    /**
     * Creates a new crypto token
     *
     * @param tokenName The name of the cryptotoken
     * @param tokenType The type of the cryptotoken. Available types: SoftCryptoToken, PKCS11CryptoToken
     * @param activationPin Pin code for the cryptotoken
     * @param autoActivate Set to true|false to allow|disallow whether cryptotoken should be autoactivated or not
     * @param cryptoTokenProperties as a List of KeyValuePair objects. See {@link org.ejbca.core.protocol.ws.objects.CryptoTokenConstantsWS}
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @see org.ejbca.core.protocol.ws.objects.CryptoTokenConstantsWS
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/createCryptoToken")
	public void createCryptoToken(String tokenName, String tokenType, String activationPin, boolean autoActivate,
	        List<KeyValuePair> cryptoTokenProperties) throws AuthorizationDeniedException, EjbcaException  {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        enterpriseWSBridgeSession.createCryptoToken(getAdmin(), tokenName, tokenType, activationPin, autoActivate,
                    cryptoTokenProperties);
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

    /**
     * Generates a key pair in the specified crypto token
     *
     * @param cryptoTokenName The name of the cryptotoken
     * @param keyPairAlias Key pair alias
     * @param keySpecification Key specification, for example RSA2048, secp256r1, DSA1024, gost3410, dstu4145
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/generateCryptoTokenKeys")
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

    /**
     * Creates a new CA using the specified crypto token
     *
     * @param caName The CA name
     * @param caDn The CA subjectDN
     * @param caType The CA type. It could be either 'x509' or 'cvc' (see the enum CaType)
     * @param validityInDays Validity of the CA in days.
     * @param certProfile Makes the CA use the certificate profile 'cert profile' instead of the default ROOTCA or SUBCA.
     * @param signAlg Signing Algorithm may be one of the following: SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA
     * SHA256WithRSAAndMGF1, SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, SHA1WithDSA,
     * GOST3411withECGOST3410, GOST3411withDSTU4145
     * @param signedByCAId The ID of a CA that will sign this CA. Use '1' for self signed CA (i.e. a root CA). For externally signed CAs, use {@link #createExternallySignedCa()}
     * @param cryptoTokenName The name of the crypto token associated with the CA
     * @param purposeKeyMapping The mapping the the crypto token keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @see org.ejbca.core.protocol.ws.objects.CAConstantsWS
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/createCA")
	public void createCA(String caName, String caDn, String caType, long validityInDays, String certProfile,
                         String signAlg, int signedByCAId, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping,
                         List<KeyValuePair> caProperties) throws EjbcaException, AuthorizationDeniedException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    logAdminName(getAdmin(),logger);
	    try {
	        String encodedValidity = "" + validityInDays +"d";
	        enterpriseWSBridgeSession.createCA(getAdmin(), caName, caDn, caType, encodedValidity, certProfile,
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

    /**
     * Creates an externally signed CA.
     *
     * @param caName The CA name
     * @param caDn The CA subjectDN
     * @param caType The CA type. It could be either 'x509' or 'cvc', from the enum {@link CaType}
     * @param validityInDays Validity of the CA in days.
     * @param certProfile Makes the CA use the certificate profile 'cert profile' instead of the default ROOTCA or SUBCA.
     * @param signAlg Signing Algorithm may be one of the following: SHA1WithRSA, SHA256WithRSA, SHA384WithRSA, SHA512WithRSA
     * SHA256WithRSAAndMGF1, SHA1withECDSA, SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, SHA1WithDSA,
     * GOST3411withECGOST3410, GOST3411withDSTU4145
     * @param cryptoTokenName The name of the crypto token associated with the CA
     * @param purposeKeyMapping The mapping the the crypto token keys and their purpose. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     * @param caProperties Optional CA properties. See {@link org.ejbca.core.protocol.ws.objects.CAConstantsWS}
     *
     * @return a CSR for the newly created CA.
     *
     * @throws EjbcaException for any failures, the true error cause will be wrapped inside.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/createExternallySignedCa")
	public byte[] createExternallySignedCa(String caName, String caDn, String caType, long validityInDays, String certProfile,
                                           String signAlg, String cryptoTokenName, List<KeyValuePair> purposeKeyMapping,
                                           List<KeyValuePair> caProperties) throws EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            logAdminName(getAdmin(),logger);
            String encodedValidity = "" + validityInDays + "d";
            return enterpriseWSBridgeSession.createExternallySignedCa(
                    getAdmin(), caName, caDn, caType, encodedValidity, certProfile, signAlg, cryptoTokenName,
                    purposeKeyMapping, caProperties
            );
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (CesecoreException e) {
            throw getEjbcaException(e, logger, e.getErrorCode(), Level.ERROR);
        }  catch (RuntimeException e) {  // ClassCastException, EJBException ...
            throw getInternalException(e, logger);
        } catch (CertPathValidatorException e) {
            throw getEjbcaException(e, logger, ErrorCode.CERT_PATH_INVALID, Level.ERROR);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

	/**
     * Adds an administrator to the specified role
     *
     * @param roleName The role to add the admin to
     * @param caName Name of the CA that issued the new administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue That value to match against
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/addSubjectToRole")
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

	/**
     * Removes an administrator from the specified role
     *
     * @param roleName The role to remove the admin from
     * @param caName Name of the CA that issued the administrator's certificate
     * @param matchWith Could be any of: NONE, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION,
              WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_COMMONNAME, WITH_UID, WITH_DNSERIALNUMBER, WITH_SERIALNUMBER,
              WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN, WITH_FULLDN
     * @param matchType Could be one of: TYPE_EQUALCASE, TYPE_EQUALCASEINS, TYPE_NOT_EQUALCASE, TYPE_NOT_EQUALCASEINS, TYPE_NONE
     * @param matchValue The value to match against
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/removeSubjectFromRole")
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

	 /**
     * Retrieves the certificates whose expiration date is before the specified number of days.
     *
     *  Note the whole certificate chain is returned.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * <p>If authorization was denied on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param days the number of days before the certificates will expire
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
	@WebMethod
	@Action(input="http://ws.protocol.core.ejbca.org/getCertificatesByExpirationTime")
    public List<Certificate> getCertificatesByExpirationTime(long days, int maxNumberOfResults) throws EjbcaException {
        final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTime(getAdmin(), days, maxNumberOfResults, 0));
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, null, ErrorCode.NOT_AUTHORIZED, Level.INFO);
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

    /**
     * List certificates that will expire within the given number of days and issued by the given issuer
     *
     * <p>If authorization was denied on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param days Expire time in days
     * @param issuerDN The issuerDN of the certificates
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
	@WebMethod
	@Action(input="http://ws.protocol.core.ejbca.org/getCertificatesByExpirationTimeAndIssuer")
    public List<Certificate> getCertificatesByExpirationTimeAndIssuer(long days, String issuer, int maxNumberOfResults)
            throws EjbcaException {
	    final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTimeAndIssuer(getAdmin(), days, issuer, maxNumberOfResults));
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, null, ErrorCode.NOT_AUTHORIZED, Level.INFO);
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

	/**
     * List certificates that will expire within the given number of days and of the given type
     *
     * <p>If authorization was denied on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param days Expire time in days
     * @param certificateType The type of the certificates. Use 0=Unknown  1=EndEntity  2=SUBCA  8=ROOTCA
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return A list of certificates, never null
     * @throws EjbcaException if at least one of the certificates is unreadable
     */
	@WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getCertificatesByExpirationTimeAndType")
    public List<Certificate> getCertificatesByExpirationTimeAndType(long days, int certificateType, int maxNumberOfResults)
            throws EjbcaException {
        final List<CertificateWrapper> certificates = new ArrayList<>();
        try {
            certificates.addAll(raMasterApiProxyBean.getCertificatesByExpirationTimeAndType(getAdmin(), days, certificateType, maxNumberOfResults));
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, null, ErrorCode.NOT_AUTHORIZED, Level.INFO);
        }
        return unwrapCertificatesOrThrowInternalException(certificates);
    }

	/**
     *  Generates a certificate for a user.
     *
     *  Works the same as {@link #pkcs10Request(String, String, String, String, String)}
     *
     *  <p>If the CA does not exist, the user could not be found or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @see #pkcs10Request(String, String, String, String, String)
     * @param username the unique username
     * @param password the password sent with editUser call
     * @param crmf the CRMF request message (only the public key is used.)
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param responseType indicating which type of answer that should be returned, on of the
     *                     {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if an object cannot be found in the database
     * @throws EjbcaException if an error occurred
     * @throws CesecoreException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/crmfRequest")
	public CertificateResponse crmfRequest(String username, String password, String crmf, String hardTokenSN, String responseType)
            throws AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        byte[] processCertReq = processCertReq(username, password, crmf, CertificateConstants.CERT_REQ_TYPE_CRMF, responseType, logger);
            return new CertificateResponse(responseType, processCertReq);
        } catch( AuthorizationDeniedException | NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (RuntimeException e) {	// ClassCastException, EJBException ...
            throw getInternalException(e, logger);
	    } finally {
	        logger.writeln();
	        logger.flush();
	    }
	}

    /**
     *  Generates a certificate for a user.
     *
     *  <p>If the CA does not exist, the user could not be found or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @see #pkcs10Request(String, String, String, String, String)
     * @param username the unique username
     * @param password the password sent with editUser call
     * @param spkac the SPKAC (netscape) request message (only the public key is used.)
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param responseType indicating which type of answer that should be returned, on of the
     *                     {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if an object cannot be found in the database
     * @throws EjbcaException if an error occurred
     * @throws CesecoreException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/spkacRequest")
	public CertificateResponse spkacRequest(String username, String password, String spkac, String hardTokenSN, String responseType)
            throws AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {

	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        byte[] processCertReq = processCertReq(username, password, spkac, CertificateConstants.CERT_REQ_TYPE_SPKAC, responseType, logger);
            return new CertificateResponse(responseType, processCertReq);
        } catch( AuthorizationDeniedException | NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (RuntimeException e) {	// EJBException ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    /**
     * Generates a CV certificate for a user.
     *
     * Uses the same authorizations as editUser and pkcs10Request
     * responseType is always {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_CERTIFICATE.
     *
     * <p>If the CA does not exist, the user could not be found or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @see #editUser(UserDataVOWS)
     * @see #pkcs10Request(String, String, String, String, String)
     * @param username the user name of the user requesting the certificate.
     * @param password the password for initial enrollment, not used for renewal requests that can be authenticated using signatures with keys with valid certificates.
     * @param cvcReq Base64 encoded CVC request message.
     * @return the full certificate chain for the IS, with IS certificate in pos 0, DV in 1, CVCA in 2.
     *
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if administrator is not authorized to edit end entity or if an authenticated request can not be verified
     * @throws SignRequestException if the provided request is invalid, for example not containing a username or password
     * @throws UserDoesntFullfillEndEntityProfile if we add or edit a profile that doesn't match its end entity profile.
     * @throws NotFoundException if an object cannot be found in the database
     * @throws EjbcaException for other errors, an error code like ErrorCode.SIGNATURE_ERROR (popo/inner signature verification failed) is set.
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws CertificateExpiredException if certificate expired.
     * @throws CesecoreException if an error occurred
     * @see org.cesecore.ErrorCode
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/cvcRequest")
    @SuppressWarnings("deprecation")
    public List<Certificate> cvcRequest(String username, String password, String cvcReq)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, NotFoundException, ApprovalException,
            EjbcaException, CesecoreException, WaitingForApprovalException, CertificateExpiredException {
        log.trace(">cvcRequest");
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        // Get and old status that we can remember so we can reset status if this fails in the last step.
        int oldUserStatus = EndEntityConstants.STATUS_GENERATED;
        try {
            final List<java.security.cert.Certificate> certificates = EJBTools.unwrapCertCollection(
                    raMasterApiProxyBean.processCardVerifiableCertificateRequest(admin, username, password, cvcReq)
            );
            final List<Certificate> result = convertCertificateCollectionToWsObjects(certificates);
            log.trace("<cvcRequest");
            return result;
        }

        catch (AuthStatusException | RuntimeException | NoSuchEndEntityException | CertificateEncodingException e) {
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, oldUserStatus);
            throw getInternalException(e, logger);
        } catch (EjbcaException e) {
            // Have this first, if processReq throws an EjbcaException we want to reset status
            ejbcaWSHelperSession.resetUserPasswordAndStatus(admin, username, oldUserStatus);
            throw e;
        } catch (CesecoreException e) {
            throw getEjbcaException(e, logger, e.getErrorCode(), Level.ERROR);
        }
        finally {
            logger.writeln();
            logger.flush();
        }
    } // cvcRequest

	/** Generates a Certificate Signing Request (CSR) from a CA. The CSR can be sent to another CA to be signed, thus making the CA a sub CA of the signing CA.
     * Can also be used for cross-certification. The method can use an existing key pair of the CA or generate a new key pair. The new key pair does not have to be
     * activated and used as the CAs operational signature keys.
     *
     * Authorization requirements: the client certificate must have the following privileges set<pre>
     * - /administrator
     * - /ca_functionality/renew_ca
     * - /ca/&lt;ca to renew&gt;
     * </pre>
     * @param caName The name in EJBCA for the CA that will create the CSR
     * @param caChain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
     * For DV renewals the CA chain may be an empty list if there is a matching imported CVCA.
     * Matching means having the same mnemonic,country and sequence as well as being external.
     * @param regenerateKeys if renewing a CA this is used to also generate a new KeyPair, if this is true and activate key is false, the new key will not be activated immediately, but added as "next" signing key.
     * @param useNextKey if regenerateKey is true this should be false. Otherwise it makes a request using an already existing "next" signing key, perhaps from a previous call with regenerateKeys true.
     * @param activateKey if regenerateKey is true or use next key is true, setting this flag to true makes the new or "next" key be activated when the request is created.
     * @param keystorePwd password used when regenerating keys or activating keys, can be null if regenerateKeys and activate key is false.
     *
     * @return byte array with binary encoded certificate request to be sent to signing CA.
     *
     * @throws CADoesntExistsException if CA name does not exist
     * @throws AuthorizationDeniedException if administrator is not authorized to create request, renew keys etc.
     * @throws ApprovalException if a non-expired approval for this action already exists, i.e. the same action has already been requested.
     * @throws WaitingForApprovalException if the operation requires approval from another CA administrator, in this case an approval request is created for another administrator to approve. The request ID will be included as a field in this exception.
     * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCode is set in the EjbcaException
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/caRenewCertRequest")
	public byte[] caRenewCertRequest(String caName, List<byte[]> caChain, boolean regenerateKeys, boolean useNextKey, boolean activateKey, String keystorePwd)
            throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
		if (log.isTraceEnabled()) {
			log.trace(">caRenewCertRequest");
		}
		if (log.isDebugEnabled()) {
		    log.debug("Create certificate request for CA "+ caName
                    + ", regeneratekeys=" + regenerateKeys
                    + ", usenextkey=" + useNextKey
                    + ", activatekey=" + activateKey
                    + ", keystorepwd: " + (keystorePwd == null ? "null" : "hidden")
            );
		}
		AuthenticationToken admin = getAdmin();
		byte[] ret;
		try {
			ret = ejbcaWSHelperSession.caRenewCertRequest(admin, caName, caChain, regenerateKeys, useNextKey, activateKey, keystorePwd);
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

    /**
     * Imports a root or sub CA certificate of an external X.509 CA or CVC CA.
     *
     * @param caName the logical name of the CA in EJBCA.
     * @param certBytes a byte array containing the CA certificate, and optional it's CA certificate chain.
     *
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws CAExistsException if a CA with that logical name or CA certificate subject DN already exists.
     * @throws EjbcaException if an other exception occurs.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/importCaCert")
	public void importCaCert(String caName, byte[] certBytes) throws AuthorizationDeniedException, EjbcaException {
	    if (log.isTraceEnabled()) {
            log.trace(">importCaCert");
        }
	    if (log.isDebugEnabled()) {
	        log.debug("Import CA certificate for new CA " + caName);
	    }
        final AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.importCaCert(admin, caName, certBytes);
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
    } 

    /**
     * Updates a root or sub CA certificate of an external X.509 CA or CVC CA.
     *
     * @param caName the logical name of the CA in EJBCA
     * @param certBytes a byte array containing the CA certificate, and optional it's CA certificate chain.
     *
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws CADoesntExistsException if a CA with that logical name does not exists in EJBCA.
     * @throws EjbcaException if an other exception occurs.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/updateCaCert")
	public void updateCaCert(String caName, byte[] certBytes) throws EjbcaException {
	    if (log.isTraceEnabled()) {
            log.trace(">updateCaCert");
        }
	    if (log.isDebugEnabled()) {
            log.debug("Update CA certificate for new CA " + caName);
        }
        try {
            ejbcaWSHelperSession.updateCaCert(getAdmin(), caName, certBytes);
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
    } 

    /** Receives a certificate as a response to a CSR from the CA. The CSR might have been generated using the caRenewCertRequest.
     * When the certificate is imported it is verified that the CA keys match the received certificate.
     * This can be used to activate a new key pair on the CA. If the certificate does not match the existing key pair, but another key pair on the CAs token, this key pair can be activated and used as the CAs operational signature key pair.
     *
     * Authorization requirements: the client certificate must have the following privileges set<pre>
     * - /administrator
     * - /ca_functionality/renew_ca
     * - /ca/&lt;ca to import certificate&gt;
     * </pre>
     * This method auto-senses if there is a new CA key that needs to be activated, it does this by comparing the public key in cert with public keys in the CAs token
     * @param caName The name in EJBCA for the CA that will create the CSR
     * @param cert the CA certificate to import. Certificate format is the binary certificate bytes.
     * @param caChain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
     * @param keystorePwd If there is a new CA key that must be activates the keystore password is needed. Set to null if the request was generated using the existing CA keys.
     *
     * @throws CADoesntExistsException if CA name does not exist
     * @throws AuthorizationDeniedException if administrator is not authorized to import certificate.
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException if the operation requires approval from another CA administrator, in this case an approval request is created for another administrator to approve. The request ID will be included as a field in this exception.
     * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCode is set in the EjbcaException
     * @throws CesecoreException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/caCertResponse")
	public void caCertResponse(String caName, byte[] cert, List<byte[]> caChain, String keystorePwd)
            throws AuthorizationDeniedException, ApprovalException, EjbcaException, WaitingForApprovalException,
            CesecoreException {
		log.trace(">caCertResponse");
		log.info("Import certificate response for CA " + caName + ", keystorepwd: " + (keystorePwd == null ? "null" : "hidden"));
		AuthenticationToken admin = getAdmin();
		try {
			ejbcaWSHelperSession.caCertResponse(admin, caName, cert, caChain, keystorePwd, false);
		} catch (CertPathValidatorException e) {
		    throw getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
		} catch (CryptoTokenOfflineException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
		} catch (CryptoTokenAuthenticationFailedException e) {
		    throw getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
		} catch (CertificateException | RuntimeException e) {
            throw getInternalException(e, null);
        }
        log.trace("<caCertResponse");
	} 

    /**
     * Receives a certificate as a response to a CSR from the CA, but does not activate the certificate yet.
     * To activate the certificate at a later point, use the rolloverCACert method.
     * It is also possible to configure a Rollover Service for automatic activation once the new certificate becomes valid.
     *
     * @param caName The name in EJBCA for the CA that will create the CSR
     * @param cert the CA certificate to import. Certificate format is the binary certificate bytes.
     * @param caChain the certificate chain for the CA this request is targeted for, the signing CA is in pos 0, it's CA (if it exists) in pos 1 etc. Certificate format is the binary certificate bytes.
     * @param keystorePwd If there is a new CA key that must be activates the keystore password is needed. Set to null if the request was generated using the existing CA keys.
     *
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws EjbcaException if an error occurred
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws CesecoreException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/caCertResponseForRollover")
    public void caCertResponseForRollover(String caName, byte[] cert, List<byte[]> caChain, String keystorePwd)
            throws AuthorizationDeniedException, ApprovalException, EjbcaException, WaitingForApprovalException,
            CesecoreException {
        log.trace(">caCertResponseWithRollover");
        log.info("Import certificate response with rollover for CA "+ caName + ", keystorepwd: " + (keystorePwd == null ? "null" : "hidden"));
        AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.caCertResponse(admin, caName, cert, caChain, keystorePwd, true);
        } catch (CertPathValidatorException e) {
            throw getEjbcaException(e, null, ErrorCode.CERT_PATH_INVALID, Level.DEBUG);
        } catch (CryptoTokenOfflineException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (CryptoTokenAuthenticationFailedException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_INVALID_TOKEN_PIN, Level.INFO);
        } catch (CertificateException | RuntimeException e) {
            throw getInternalException(e, null);
        }
        log.trace("<caCertResponseWithRollover");
    } 

    /**
     * Performs a certificate rollover for a CA with a rollover certificate previously added with caCertResponseForRollover.
     * @throws AuthorizationDeniedException if administrator is not authorized to import certificate.
     * @throws CADoesntExistsException if CA name does not exist
     * @throws EjbcaException other errors in which case an org.ejbca.core.ErrorCode is set in the EjbcaException
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/rolloverCACert")
    public void rolloverCACert(String caName) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        log.trace(">rolloverCACert");
        log.info("Rollover to next certificate for CA "+ caName);
        AuthenticationToken admin = getAdmin();
        try {
            ejbcaWSHelperSession.rolloverCACert(admin, caName);
        } catch (CryptoTokenOfflineException e) {
            throw getEjbcaException(e, null, ErrorCode.CA_OFFLINE, Level.INFO);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, null);
        }
        log.trace("<rolloverCACert");
    } 

    /**
     * Generates a certificate for a user.
     *
     * The method must be preceded by
     * a editUser call, either to set the user status to 'new' or to add non-existing users.
     *
     * Observe, the user must first have added/set the status to new with edituser command
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca_functionality/create_certificate
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * @param username the unique username
     * @param password the password sent with editUser call
     * @param pkcs10 the base64 encoded PKCS10 (only the public key is used.)
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param responseType indicating which type of answer that should be returned, on of the
     * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
     * @return the generated certificate, in either just X509Certificate or PKCS7
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if user cannot be found
     * @throws EjbcaException if an error occurred
     * @throws CesecoreException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/pkcs10Request")
	public CertificateResponse pkcs10Request(final String username, final String password, final String pkcs10, final String hardTokenSN, final String responseType)
	throws AuthorizationDeniedException, NotFoundException, EjbcaException, CesecoreException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	    	if (log.isDebugEnabled()) {
	    		log.debug("PKCS10 from user '"+username+"'.");
	    	}
	        return new CertificateResponse(
	                responseType,
                    processCertReq(username, password, pkcs10, CertificateConstants.CERT_REQ_TYPE_PKCS10, responseType, logger)
            );
        } catch( AuthorizationDeniedException | NotFoundException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    private byte[] processCertReq(final String username, final String password, final String req, final int reqType,
            final String responseType, final IPatternLogger logger)
            throws EjbcaException, CesecoreException, AuthorizationDeniedException {
        byte[] result;
        try {
            final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            result = raMasterApiProxyBean.processCertificateRequest(admin, username, password, req, reqType, null, responseType);
        } catch (CertificateExtensionException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException | IOException | ParseException | ConstructionException | NoSuchFieldException | RuntimeException e) {
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
        }
        catch(EjbcaException e) {
            // Log exception with logger not injected into RA master API call.
            throw getEjbcaException(e.getMessage(), logger, ErrorCode.BAD_USER_TOKEN_TYPE, null);
        }
        return result;
    }

    /**
     * Creates a server-generated keystore.
     *
     * The method must be preceded by
     * a editUser call, either to set the user status to 'new' or to add non-existing users and
     * the user's token must be set to {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS}.TOKEN_TYPE_P12.<br>
     *
     * Authorization requirements: <pre>
     * - /administrator
     * - /ca/&lt;ca of user&gt;
     * - /ca_functionality/create_certificate
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ra_functionality/view_end_entity
     * </pre>
     *
     * Additional authorization requirements for (non key recovery) clearing of password: <pre>
     * - /endentityprofilesrules/&lt;end entity profile&gt;/edit_end_entity
     * - /ra_functionality/edit_end_entity
     * </pre>
     *
     * Additional authorization requirements for key recovery: <pre>
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /ra_functionality/keyrecovery
     * </pre>
     *
     * <p>If the CA does not exist, the user could not be found or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param username the unique username
     * @param password the password sent with editUser call
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param keySpec that the generated key should have, examples are 2048 for RSA or secp256r1 for ECDSA.
     * @param keyAlg that the generated key should have, RSA, ECDSA. Use one of the constants in
     * {@link com.keyfactor.util.crypto.algorithm.AlgorithmConstant}.KEYALGORITHM_...
     * @return the generated keystore
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if user cannot be found
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/pkcs12Req")
	public KeyStore pkcs12Req(String username, String password, String hardTokenSN, String keySpec, String keyAlg)
		throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
		    final AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
            return new KeyStore(raMasterApiProxyBean.generateOrKeyRecoverToken(admin, username, password, hardTokenSN, keySpec, keyAlg), password);
		} catch (RuntimeException e) {
            throw getInternalException(e, logger);
		} catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.INFO);
        } catch(EjbcaException e) {
            throw getEjbcaException(e.getMessage(), logger, e.getErrorCode(), null);
        } // EJBException, ...
        finally {
            logger.writeln();
            logger.flush();
		}
	}

	private void revokeCert(CertRevocationDto certRevocationDto, IPatternLogger logger)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException,
            RevokeBackDateNotAllowedForProfileException, EjbcaException, WaitingForApprovalException,
            CertificateProfileDoesNotExistException {

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

	/**
     * Same as {@link #revokeCertBackdated(String, String, int, String)} but revocation date is current time.
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param issuerDN issuer DN
     * @param certificateSN certificate SN
     * @param reason reason
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if an object cannot be found in the database
     * @throws EjbcaException if an error occurred
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws AlreadyRevokedException if certificate was already revoked, or you tried to unrevoke a permanently revoked certificate
     */
	@WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/revokeCert")
	public void revokeCert(final String issuerDN, final String certificateSN, final int reason)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException,
            ApprovalException, EjbcaException, WaitingForApprovalException {
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

	/**
     * Revokes a user certificate.
     *
     * Authorization requirements:<pre>
     * - Administrator flag set
     * - /administrator
     * - /ra_functionality/revoke_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of the user owning the cert&gt;/revoke_end_entity
     * - /ca/&lt;ca of certificate&gt;
     * </pre>
     * <p>
     * To use this call the certificate to be used must be from a certificate profile that has 'Allow back dated revocation' enabled.
     * </p>
     * <p>If {@link RevokeBackDateNotAllowedForProfileException} is thrown then the CA is not
     * allowing back date and you could then revoke with {@link #revokeCert(String, String, int)}.
     * {@link DateNotValidException} means that the date parameter can't be parsed and in this case it might also
     * be better with a fall back to {@link #revokeCert(String, String, int)}.
     * </p>
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param issuerDN of the certificate to revoke
     * @param certificateSN Certificate serial number in hex format of the certificate to revoke (without any "0x", "h" or similar)
     * @param reason for revocation, one of {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.REVOKATION_REASON_ constants,
     * or use {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.NOT_REVOKED to un-revoke a certificate on hold.
     * @param sDate The revocation date. If null then the current date is used. If specified then the profile of the certificate must allow
     * "back dating" and the date must be i the past. The parameter is specified as an
     * <a href="http://en.wikipedia.org/wiki/ISO8601">ISO 8601 string</a>.
     * An example: 2012-06-07T23:55:59+02:00
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws NotFoundException if certificate doesn't exist
     * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
     * @throws ApprovalException There already exists an approval request for this task.
     * @throws AlreadyRevokedException The certificate was already revoked, or you tried to unrevoke a permanently revoked certificate
     * @throws EjbcaException internal error
     * @throws RevokeBackDateNotAllowedForProfileException if back date is not allowed in the certificate profile
     * @throws DateNotValidException if the date is not a valid ISO 8601 string or if it is in the future.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/revokeCertBackdated")
	public void revokeCertBackdated(final String issuerDN, final String certificateSN, final int reason, String sDate)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException,
            ApprovalException, RevokeBackDateNotAllowedForProfileException, EjbcaException, WaitingForApprovalException {
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

    /**
    * Revokes a user certificate. Allows to specify column values via metadata input param.
    * Metadata is a list of key-value pairs, keys can be for example: certificateProfileId, reason, revocation date
    *
    * <p>If the CA does not exist on the local system, then the request will be forwarded to upstream peer systems (if any).</p>
    *
    * @throws CADoesntExistsException if a referenced CA does not exist
    * @throws AuthorizationDeniedException if client isn't authorized.
    * @throws NotFoundException if certificate doesn't exist
    * @throws EjbcaException internal error
    * @throws ApprovalException There already exists an approval request for this task
    * @throws WaitingForApprovalException If request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
    * @throws AlreadyRevokedException The certificate was already revoked, or you tried to unrevoke a permanently revoked certificate
    * @throws RevokeBackDateNotAllowedForProfileException if back date is not allowed in the certificate profile
    * @throws DateNotValidException if the date is not a valid ISO 8601 string or if it is in the future.
    * @throws CertificateProfileDoesNotExistException if no profile was found with certRevocationDto.certificateProfileId input parameter.
    */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/revokeCertWithMetadata")
    public void revokeCertWithMetadata(final String issuerDN, final String certificateSN, final List<KeyValuePair> metadata)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException,
            RevokeBackDateNotAllowedForProfileException, ApprovalException, EjbcaException, WaitingForApprovalException,
            CertificateProfileDoesNotExistException {
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

    CertRevocationDto parseRevocationMetadata(CertRevocationDto certRevocationDto, final List<KeyValuePair> metadata)
            throws DateNotValidException {
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

	/**
     * Revokes all of a user's certificates.
     *
     * It is also possible to delete a user after all certificates have been revoked.
     *
     * If the request is proxied to another EJBCA instance, at least one revocation must succeed or the operation fails with the last exception thrown.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/revoke_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/revoke_end_entity
     * - /ca/<ca of users certificate>
     * </pre>
     *
     * <p>If the CA does not exist, the user could not be found, or its waiting for approval, approval was denied, is revoked
     *    already or could not be deleted on the local system, then the request will be forwarded to upstream peer systems (if any).
     *    The requested is processed on all instances available.</p>
     *
     * @param username unique username in EJBCA.
     * @param reason for revocation, one of {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.REVOKATION_REASON_ constants
     * or use {@link org.ejbca.core.protocol.ws.client.gen.RevokeStatus}.NOT_REVOKED to un-revoke a certificate on hold.
     * @param deleteUser deletes the users after all the certificates have been revoked.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws NotFoundException if user doesn't exist.
     * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
     * @throws ApprovalException if there already exists an approval request for this task.
     * @throws AlreadyRevokedException if the user already was revoked.
     * @throws EjbcaException any EjbcaException.
     * @see RevokeStatus
     */
	@WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/revokeUser")
	public void revokeUser(String username, int reason, boolean deleteUser)
            throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, AlreadyRevokedException,
            ApprovalException, EjbcaException, WaitingForApprovalException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			final AuthenticationToken admin = getAdmin();
            logAdminName(admin, logger);
            raMasterApiProxyBean.revokeUser(admin, username, reason, deleteUser);
		} catch (NoSuchEndEntityException e) {
		    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
		    throw new NotFoundException(intres.getLocalizedMessage("ra.wrongusernameorpassword"));
		} catch (CouldNotRemoveEndEntityException | RuntimeException e) {
            throw getInternalException(e, logger);
        }
        finally {
            logger.writeln();
            logger.flush();
        }
	}

    /**
     * Marks the user's latest certificate for key recovery.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/keyrecovery
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /ca/&lt;ca of users certificate&gt;
     * </pre>
     *
     * @param username unique username in EJBCA
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws NotFoundException if user doesn't exist
     * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
     * @throws ApprovalException if there already exists an approval request for this task
     * @throws EjbcaException if there is a configuration or other error
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/keyRecoverNewest")
	public void keyRecoverNewest(String username) throws CADoesntExistsException, AuthorizationDeniedException,
            NotFoundException, ApprovalException, EjbcaException, WaitingForApprovalException {
		log.trace(">keyRecoverNewest");
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try{
			AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);

            boolean useKeyRecovery =((GlobalConfiguration)  globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            if(!useKeyRecovery){
				throw getEjbcaException("Keyrecovery have to be enabled in the system configuration in order to use this command.",
                                        logger, ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, null);
            }
			EndEntityInformation userData = endEntityAccessSession.findUser(admin, username);
			if(userData == null){
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
				throw new NotFoundException(msg);
			}
			if(keyRecoverySession.isUserMarked(username)){
				// User is already marked for recovery.
				return;
			}
			// check CAID
			int caId = userData.getCAId();
			caSession.verifyExistenceOfCA(caId);
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caId)) {
	            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() +caId, null);
		        throw new AuthorizationDeniedException(msg);
            }

			// Do the work, mark user for key recovery
			endEntityManagementSession.prepareForKeyRecovery(admin, userData.getUsername(), userData.getEndEntityProfileId(), null);
        } catch (RuntimeException e) {	// EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		log.trace("<keyRecoverNewest");
	}

    /**
     * Marks a user's certificate for key recovery.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of users certificate&gt;
     * - /ca_functionality/view_certificate
     * - /ra_functionality/keyrecovery
     * - /ra_functionality/view_end_entity
     * </pre>
     *
     * @param username unique username in EJBCA
     * @param certSNinHex unique certificate serialnumber in EJBCA, hex encoded
     * @param issuerDN DN of CA, in EJBCA, that issued the certificate
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws NotFoundException if user doesn't exist
     * @throws WaitingForApprovalException if request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
     * @throws ApprovalException if there already exists an approval request for this task
     * @throws EjbcaException if there is a configuration or other error
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/keyRecover")
    public void keyRecover(String username, String certSNinHex, String issuerDN) throws CADoesntExistsException,
            AuthorizationDeniedException, NotFoundException, ApprovalException, EjbcaException,
            WaitingForApprovalException {
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
        } catch (AuthorizationDeniedException | CADoesntExistsException | WaitingForApprovalException | EjbcaException e) {
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

    /**
     * Key recovers specified certificate and generates a new keystore in one
     * atomic operation.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;/keyrecovery
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of users certificate&gt;
     * - /ca_functionality/view_certificate
     * - /ca_functionality/create_certificate
     * - /ra_functionality/view_end_entity
     * - /ra_functionality/keyrecovery
     * </pre>
     * @param username unique username (end entity) in EJBCA
     * @param certSNinHex unique certificate serial number in EJBCA, hex encoded
     * @param issuerDN DN of CA, in EJBCA, that issued the certificate
     * @param password new password
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @return the generated keystore
     * @throws AuthorizationDeniedException if the requesting administrator is unauthorized to perform this operation
     * @throws CADoesntExistsException referenced CA cannot be found in any EJBCA instance
     * @throws WaitingForApprovalException if the request has bean added to list of tasks to be approved. The request ID will be included as a field in this exception.
     * @throws EjbcaException other exceptions
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/keyRecoverEnroll")
    public KeyStore keyRecoverEnroll(String username, String certSNinHex, String issuerDN, String password, String hardTokenSN)
            throws AuthorizationDeniedException, NotFoundException, EjbcaException, CADoesntExistsException,
            WaitingForApprovalException {
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
        } catch (AuthorizationDeniedException | CADoesntExistsException | WaitingForApprovalException | EjbcaException e) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), e.toString());
            throw e;
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    /**
     * Returns revocation status for given user.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ca/&lt;ca of certificate&gt;
     * </pre>
     *
     * @param issuerDN issuer DN
     * @param certificateSN a hexa decimal string
     * @return the revocation status or null if certificate does not exist.
     *         For CAs in throw-away mode and with the option "accept revocation of
     *         non-existing entries", this function returns OK for non-existing entries.
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized.
     * @throws EjbcaException if an error occurred
     * @see RevokeStatus
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/checkRevokationStatus")
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();

		try{
		  AuthenticationToken admin = getAdmin();
          logAdminName(admin,logger);
          // The method over RA Master API will also check if the CA (issuer DN) is something we handle and throw a CADoesntExistsException if not
		  // It also checks if we are authorized to the CA, and throws AuthorizationDeniedException if not
          CertificateStatus certInfo = raMasterApiProxyBean.getCertificateStatus(admin, issuerDN, new BigInteger(certificateSN,16));
		  // If certificate is not available, pass this and return null
		  if(certInfo != null && !certInfo.equals(CertificateStatus.NOT_AVAILABLE)){
		    return new RevokeStatus(certInfo, issuerDN, certificateSN);
		  }
		  return null;
        } catch (DatatypeConfigurationException | RuntimeException e) {
            throw getInternalException(e, logger);
        }
        finally {
            logger.writeln();
            logger.flush();
        }
	}


    /**
     * Checks if a user is authorized to a given resource.
     *
     * Authorization requirements: a valid client certificate
     *
     * <p> This request will be process locally and is forwarded upstream peer systems (if any)
     *     until an instance with an active CA was found there the authorization can be verified. </p>
     *
     * @param resource the access rule to test
     * @return true if the user is authorized to the resource otherwise false.
     * @throws EjbcaException if an error occurred
     * @see RevokeStatus
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/isAuthorized")
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

    /**
     * Fetches user data from an existing UserDataSource.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /userdatasourcesrules/&lt;user data source&gt;/fetch_userdata (for all the given user data sources)
     * - /ca/&lt;all cas defined in all the user data sources&gt;
     * </pre>
     *
     * If not turned of in jaxws.properties then only a valid certificate required
     *
     *
     * @param userDataSourceNames a List of User Data Source Names
     * @param searchString to identify the userdata.
     * @return a List of UserDataSourceVOWS of the data in the specified UserDataSources, if no user data is found will an empty list be returned.
     * @throws UserDataSourceException if an error occurred connecting to one of UserDataSources
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/fetchUserData")
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws EjbcaException, AuthorizationDeniedException{
		final AuthenticationToken admin;
		if(WebServiceConfiguration.getNoAuthorizationOnFetchUserData()){
			final AuthenticationToken tmp = getAdmin(true);
			// We know client certificate is needed, so no other authentication tokens can exist
			X509Certificate adminCert = ((X509CertificateAuthenticationToken)tmp).getCertificate();
			admin = new AlwaysAllowLocalAuthenticationToken(adminCert.getSubjectDN().getName());
		}else{
			admin = getAdmin();
		}

		final ArrayList<UserDataSourceVOWS> returnValues = new ArrayList<>();

        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
			final ArrayList<Integer> userDataSourceIds = new ArrayList<>();
            for (String name : userDataSourceNames) {
                final int id = userDataSourceSession.getUserDataSourceId(admin, name);
                if (id != 0) {
                    userDataSourceIds.add(id);
                } else {
                    log.error("Error User Data Source with name : " + name + " doesn't exist.");
                }
            }
            for (UserDataSourceVO next : userDataSourceSession.fetch(admin, userDataSourceIds, searchString)) {
                returnValues.add(new UserDataSourceVOWS(ejbcaWSHelperSession.convertEndEntityInformation(next.getEndEntityInformation()), next.getIsFieldModifyableSet()));
            }
        } catch (CADoesntExistsException e) {	// EJBException, ClassCastException, ...
            throw getEjbcaException(e, logger, ErrorCode.CA_NOT_EXISTS, Level.INFO);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
        return returnValues;
	}

    /**
     * Republishes a selected certificate.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param serialNumberInHex of the certificate to republish
     * @param issuerDN of the certificate to republish
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if the administrator isn't authorized to republish
     * @throws PublisherException if something went wrong during publication
     * @throws EjbcaException if other error occurred on the server side.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/republishCertificate")
	public void republishCertificate(String serialNumberInHex, String issuerDN) throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException{
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

    /**
     * Generates a Custom Log event in the database. In a setup with connected peer systems,
     * the log entry is written at the first peer where the CA exists, starting with remote systems,
     * then the local system.
     *
     * Authorization requirements: <pre>
     * - /administrator
     * - /secureaudit/log_custom_events (must be configured in advanced mode when editing access rules)
     * </pre>
     *
     * <p>If the CA does not exist or authorization was denied on the local system, then the request will
     *    be forwarded to upstream peer systems (if any).</p>
     *
     * @param level of the event, one of IEjbcaWS.CUSTOMLOG_LEVEL_ constants
     * @param type userdefined string used as a prefix in the log comment
     * @param caName of the ca related to the event, use null if no specific CA is related.
     * Then will the ca of the administrator be used.
     * @param username of the related user, use null if no related user exists.
     * @param certificate that relates to the log event, use null if no certificate is related
     * @param msg message data used in the log comment. The log comment will have
     * a syntax of 'type : msg'
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if the administrators isn't authorized to log.
     * @throws EjbcaException if error occurred server side
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/customLog")
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
		} catch (CertificateException | RuntimeException e) {
            throw getInternalException(e, logger);
        } // EJBException, ClassCastException, ...
        finally {
            logger.writeln();
            logger.flush();
        }
	}

    /**
     * Removes user data from a user data source.
     *
     * Important removal functionality of a user data source is optional to
     * implement so it isn't certain that this method works with the given
     * user data source.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /userdatasourcesrules/&lt;user data source&gt;/remove_userdata (for all the given user data sources)
     * - /ca/&lt;all cas defined in all the user data sources&gt;
     * </pre>
     *
     * @param userDataSourceNames the names of the userdata source to remove from
     * @param searchString the search string to search for
     * @param removeMultipleMatch if multiple matches of a search string should be removed otherwise is none removed.
     * @return true if the user was remove successfully from at least one of the user data sources.
     * @throws AuthorizationDeniedException if the user isn't authorized to remove userdata from any of the specified user data sources
     * @throws MultipleMatchException if the search string resulted in a multiple match and the removeMultipleMatch was set to false.
     * @throws UserDataSourceException if an error occurred during the communication with the user data source.
     * @throws EjbcaException if error occurred server side
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/deleteUserDataFromSource")
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, EjbcaException {
		boolean returnValue;
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			AuthenticationToken admin = getAdmin();
            logAdminName(admin,logger);
			ArrayList<Integer> userDataSourceIds = new ArrayList<>();
            for (String nextName : userDataSourceNames) {
                int id = userDataSourceSession.getUserDataSourceId(admin, nextName);
                if (id == 0) {
                    throw new UserDataSourceException("Error: User Data Source with name : " + nextName + " couldn't be found, aborting operation.");
                }
                userDataSourceIds.add(id);
            }
			returnValue = userDataSourceSession.removeUserData(admin, userDataSourceIds, searchString, removeMultipleMatch);
        } catch (RuntimeException e) {	// EJBException, ClassCastException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
		return returnValue;
	}

    /**
     * Looks up if a requested action has been approved. <b>Note:</b> This method uses the "approvalId" hash to identify the approval.
     * The hash is generated by ApprovalRequest.generateApprovalId(),
     * which is implemented in each of the ApprovalRequest sub classes. It is the same for identical approval requests, so you can create an
     * ApprovalRequest object with the same parameters and call the generateApprovalId method to obtain the approvalId hash.
     * <p>
     * If you have a requestId, please use {@link #getRemainingNumberOfApprovals} instead.
     * <p>
     * Authorization requirements: A valid certificate
     * <p>
     * If an approval was found but it is pending or suspended on the local system,
     * then the request will be forwarded to upstream peer systems (if any).
     *
     * @param approvalId unique hash for the action, generated by ApprovalRequest.generateApprovalId(). Note that this is <b>not</b> the same as requestId. Please use {@link #getRemainingNumberOfApprovals} if you have a requestId.
     * @return the number of approvals left, 0 if approved otherwise is the ApprovalDataVO.STATUS constants returned indicating the status. If the request was proxied to a CA instance, and the request fails for technical reasons -9 is returned.
     * @throws ApprovalException if approvalId does not exist
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it won't throw it anymore.
     * @throws EjbcaException if error occurred server side
     * @see #getRemainingNumberOfApprovals
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/isApproved")
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException {
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

    /**
     * Returns the number of remaining approvals.
     * <p>
     * If an approval was found but it is pending or suspended on the local system,
     * then the request will be forwarded to upstream peer systems (if any).
     *
     * @param requestId the ID of an approval request. This value can be obtained from {@link WaitingForApprovalException#getRequestId}
     * @return the remaining number of approvals for this request (with 0 meaning that the request has passed) or -1 if the request has been denied. If the request was proxied to a CA instance, and the request fails for technical reasons -9 is returned.
     * @throws ApprovalException if a request of the given ID didn't exist
     * @throws AuthorizationDeniedException if the current requester wasn't authorized.
     * @throws ApprovalRequestExpiredException if approval request was expired before having a definite status
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getRemainingNumberOfApprovals")
    public int getRemainingNumberOfApprovals(int requestId)
            throws ApprovalException, AuthorizationDeniedException, ApprovalRequestExpiredException {
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

    /**
     * Fetches an issued certificate. If the request is proxied, the certificate on the first proxied instance found is returned.
     *
     * Authorization requirements:<pre>
     * - A valid certificate
     * - /ca_functionality/view_certificate
     * - /ca/&lt;of the issing CA&gt;
     * </pre>
     *
     * <p>If the CA does not exist or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param certSNinHex the certificate serial number in hexadecimal representation
     * @param issuerDN the issuer of the certificate
     * @return the certificate (in WS representation) or null if certificate couldn't be found.
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if the calling administrator isn't authorized to view the certificate
     * @throws EjbcaException if error occurred server side
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getCertificate")
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
        } catch (CertificateEncodingException | RuntimeException e) {
            throw getInternalException(e, logger);
        }
        finally {
            logger.writeln();
            logger.flush();
        }
        return result;
    }

    /**
     * Fetch a list of the ids and names of available CAs.
     *
     * Note: available means not having status "external" or "waiting for certificate response".
     *
     * Authorization requirements:<pre>
     * - /administrator
     * </pre>
     *
     * If not turned of in jaxws.properties then only a valid certificate required
     *
     * <p>If the local system is not a CA, then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @return array of NameAndId of available CAs, if no CAs are found will an empty array be returned of size 0, never null.
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getAvailableCAs")
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

    /**
     * Fetches the end-entity profiles that the administrator is authorized to use.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * @return array of NameAndId of available end entity profiles, if no profiles are found will an empty array be returned of size 0, never null.
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getAuthorizedEndEntityProfiles")
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

    /**
     * Fetches available certificate profiles in an end entity profile.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * @param entityProfileId id of an end entity profile where we want to find which certificate profiles are available
     * @return array of NameAndId of available certificate profiles, if no profiles are found will an empty array be returned of size 0, never null.
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getAvailableCertificateProfiles")
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

    /**
     * Fetches the ids and names of available CAs in an end entity profile.
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /endentityprofilesrules/&lt;end entity profile&gt;
     * </pre>
     *
     * If not turned of in jaxws.properties then only a valid certificate required
     *
     * <p>If the end entity profile does not exist or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param entityProfileId id of an end entity profile where we want to find which CAs are available
     * @return array of NameAndId of available CAs in the specified end entity profile, if no CAs are found will an empty array be returned of size 0, never null.
     * @throws EjbcaException if an error occurred
     * @throws AuthorizationDeniedException if client isn't authorized to request
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getAvailableCAsInProfile")
    public NameAndId[] getAvailableCAsInProfile(final int entityProfileId)
            throws AuthorizationDeniedException, EjbcaException {
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

    /**
     * Fetches the profile specified by profileId and profileType in XML format.
     *
     * Authorization requirements for an EEP:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity_profiles
     * - any CA's referenced to in the EEP, or in any CPs referenced to in the EEP
     * </pre>
     *
     * Authorization requirements for an CP:<pre>
     * - /administrator
     * - /ca_functionality/view_certificate_profiles
     * - any CA's referenced to in the CP
     * </pre>
     *
     * For detailed documentation for how to parse an End Entity Profile XML, see the org.ejbca.core.model.ra.raadmin.EndEntity class.
     *
     * <p>If the end entity profile (or certificate profile) does not exist or authorization was denied on the local system,
     *    then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param profileId ID of the profile we want to retrieve.
     * @param profileType The type of the profile we want to retrieve. 'eep' for End Entity Profiles and 'cp' for Certificate Profiles
     * @return a byte array containing the specified profile in XML format
     * @throws EjbcaException if a profile of the specified type was not found
     * @throws AuthorizationDeniedException if the requesting user wasn't authorized to the requested profile
     * @throws UnknownProfileTypeException if the submitted profile type was not 'eep' or 'cp'
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getProfile")
    public byte[] getProfile(int profileId, String profileType)
            throws AuthorizationDeniedException, UnknownProfileTypeException, EjbcaException {
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

    /**
     * Generates a CRL for the given CA.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * @param caName the name in EJBCA of the CA that should have a new CRL generated
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws EjbcaException if an error occurred, for example authorization denied
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it won't throw it anymore.
     * @throws CAOfflineException if CA is offline.
     * @throws CryptoTokenOfflineException if CA Token that isn't available
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/createCRL")
	public void createCRL(String caName) throws CADoesntExistsException, ApprovalException, EjbcaException,
            CryptoTokenOfflineException, CAOfflineException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
		try {
			AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            CAInfo cainfo = caSession.getCAInfo(admin, caName);
            if (cainfo == null) {
                throw new CADoesntExistsException("CA with name " + caName + " doesn't exist.");
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

	/**
     * Retrieves the latest CRL issued by the given CA.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param caName the name in EJBCA of the CA that issued the desired CRL
     * @param deltaCRL false to fetch a full CRL, true to fetch a deltaCRL (if issued)
     * @return the latest CRL issued for the CA as a DER encoded byte array
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws EjbcaException if an error occurred, for example authorization denied
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getLatestCRL")
    public byte[] getLatestCRL(final String caName, final boolean deltaCRL)
            throws CADoesntExistsException, EjbcaException {
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        try {
            final AuthenticationToken admin = getAdmin(true);
            logAdminName(admin,logger);
            return raMasterApiProxyBean.getLatestCrl(admin, caName, deltaCRL);
        } catch (AuthorizationDeniedException e) {
            throw getEjbcaException(e, logger, ErrorCode.NOT_AUTHORIZED, Level.ERROR);
        } catch (RuntimeException e) {  // EJBException, ...
            throw getInternalException(e, logger);
        } finally {
            logger.writeln();
            logger.flush();
        }
    }

    /**
     * Retrieves the latest CRL issued by the given CA.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param caName the name in EJBCA of the CA that issued the desired CRL
     * @param deltaCRL false to fetch a full CRL, true to fetch a deltaCRL (if issued)
     * @param crlPartitionIndex a CRL partition index. 0 if CRL has no partitions
     * @return the latest CRL issued for the CA as a DER encoded byte array
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws EjbcaException if an error occurred, for example authorization denied
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getLatestCRLPartition")
    public byte[] getLatestCRLPartition(String caName, boolean deltaCRL, int crlPartitionIndex)
            throws CADoesntExistsException, EjbcaException {
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

    /**
     * Returns the version of the EJBCA server.
     *
     * Authorization requirements:
     *  - none
     *
     * @return String with the version of EJBCA, i.e. "EJBCA 3.6.2"
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getEjbcaVersion")
	public String getEjbcaVersion() {
		return GlobalConfiguration.EJBCA_VERSION;
	}

    /**
     * Returns the length of a publisher queue.
     *
     * If the request is proxied from the RA to CA instances, the result of the first queue found is returned,
     * to not to count the queue length multiple times on a cluster environment. Therefore the method MUST NOT be
     * called for deployment scenarios, where the request is proxied to multiple different CA instances not sharing
     * the same data store.
     *
     * <p>If the publisher does not exist on the local system, then the request will be forwarded
     *    to upstream peer systems (if any).</p>
     *
     * @param name of the queue
     * @return the length or -4 if the publisher does not exist.
     * @throws EjbcaException if an error occurred
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getPublisherQueueLength")
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

    /**
     * Generates a certificate for a user.
     * If the user is not already present in the database it will be added otherwise it will be overwritten.<br>
     * Status is automatically set to STATUS_NEW.<p>
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/create_end_entity and/or edit_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
     * - /ca_functionality/create_certificate
     * - /ca/&lt;ca of user&gt;
     * </pre>
     * When the requestType is PUBLICKEY the requestData should be an
     * SubjectPublicKeyInfo structure either base64 encoded or in PEM format.
     *
     * <p>If the CA does not exist on the local system, then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * Using this call to create end entities on CAs/Certificate Profiles with approval restrictions is not possible. If such a usecase is desired,
     * use org.ejbca.core.protocol.ws.common.IEjbcaWS.editUser(UserDataVOWS) in conjunction with
     * org.ejbca.core.protocol.ws.common.IEjbcaWS.getRemainingNumberOfApprovals(int) and
     * org.ejbca.core.protocol.ws.common.IEjbcaWS.pkcs10Request(String, String, String, String, String) instead.
     *
     * @param userData the user
     * @param requestData the PKCS10/CRMF/SPKAC/PUBLICKEY request in base64
     * @param requestType PKCS10, CRMF, SPKAC or PUBLICKEY request as specified by
     * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.CERT_REQ_TYPE_ parameters.
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param responseType indicating which type of answer that should be returned, on of the
     * {@link org.ejbca.core.protocol.ws.common.CertificateHelper}.RESPONSETYPE_ parameters.
     * @return the generated certificate, in either just X509Certificate or PKCS7
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if user cannot be found
     * @throws UserDoesntFullfillEndEntityProfile if we add or edit a profile that doesn't match its end entity profile.
     * @throws ApprovalException thrown if a end needs to be created as part of this request, but that action requires approvals.
     * @throws WaitingForApprovalException never thrown, but remains for legacy reasons.
     * @throws EjbcaException if an error occurred
     * @see #editUser(UserDataVOWS)
     */
    @SuppressWarnings("deprecation")
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/certificateRequest")
    public CertificateResponse certificateRequest(final UserDataVOWS userData, final String requestData, final int requestType, final String hardTokenSN, final String responseType)
	        throws AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile, ApprovalException,
            EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	    	if (log.isDebugEnabled()) {
	    		log.debug("CertReq for user '" + userData.getUsername() + "'.");
	    	}
	        setUserDataVOWS(userData);
	    	final AuthenticationToken admin = getAdmin(false);
	    	logAdminName(admin,logger);
	        return new CertificateResponse(responseType, raMasterApiProxyBean.createCertificateWS(admin, userData, requestData, requestType,
	                null, responseType));
	    } catch( AuthorizationDeniedException | NotFoundException t ) {
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

    /**
     * Enrolls (if the end entity doesn't already exist) and issues an SSH certificate
     *
     * @param userDataVOWS a value object for the end entity.
     *  and critical options for this end entity.
     * @param sshRequestMessage a SshRequestMessageWs containing all pertinent request details
     * @return the SSH certificate in OpenSSH format, as a byte array
     * @throws AuthorizationDeniedException if the caller doesn't have authorization to enroll end entities
     * @throws EjbcaException if an error occurred
     * @throws EndEntityProfileValidationException if someone tries to add or edit an end entity that doesn't match its profile.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/enrollAndIssueSshCertificate")
    public byte[] enrollAndIssueSshCertificate(final UserDataVOWS userDataVOWS, final SshRequestMessageWs sshRequestMessageWs)
            throws AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException {
        if (!CAFactory.INSTANCE.existsCaType(SshCa.CA_TYPE)) {
            throw new UnsupportedOperationException("SSH module does not exist on this instance of EJBCA.");
        } else {
            setUserDataVOWS(userDataVOWS);
            try {
                SshRequestMessage sshRequestMessage = ejbcaWSHelperSession.convertSshRequestMessage(sshRequestMessageWs);
                sshRequestMessage.setUsername(userDataVOWS.getUsername());
                sshRequestMessage.setPassword(userDataVOWS.getPassword());
                return raMasterApiProxyBean.enrollAndIssueSshCertificateWs(getAdmin(), userDataVOWS, sshRequestMessage);
            } catch (EjbcaException e) {
                Level loglevel = Level.DEBUG;
                if (e.getErrorCode() != null) {
                    final String err = e.getErrorCode().getInternalErrorCode();
                    // Don't log at ERROR log level for the following cases (for example):
                    //   - user's key length too small (ILLEGAL_KEY)
                    //   - wrong user status (USER_WRONG_STATUS)
                    //   - other EjbcaExceptions and CESeCoreExceptions
                    if (ErrorCode.INTERNAL_ERROR.getInternalErrorCode().equals(err) || ErrorCode.SIGNATURE_ERROR.getInternalErrorCode().equals(err)
                            || ErrorCode.INVALID_KEY.getInternalErrorCode().equals(err) || ErrorCode.LOGIN_ERROR.getInternalErrorCode().equals(err)
                            || ErrorCode.INVALID_KEY_SPEC.getInternalErrorCode().equals(err)) {
                        loglevel = Level.ERROR;
                    }
                }
                log.log(loglevel, "EJBCA WebService error", e);
                throw e;
            }
        }
    }

    /**
     * Generates a soft token certificate for a user.
     * If the user is not already present in the database, the user is added.<br>
     * Status is automatically set to STATUS_NEW.<br>
     * The user's token type must be set to {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS}.TOKEN_TYPE_ (JKS or P12).
     * A token password must also be defined.<p>
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/create_end_entity and/or edit_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of user&gt;/create_end_entity and/or edit_end_entity
     * - /ca_functionality/create_certificate
     * - /ca/&lt;ca of user&gt;
     * </pre>
     * @param userData the user
     * @param hardTokenSN Hard Token support was dropped since 7.1.0. Use null as this parameter
     * @param keySpec that the generated key should have, examples are 2048 for RSA or secp256r1 for ECDSA.
     * @param keyAlg that the generated key should have, RSA, ECDSA. Use one of the constants in
     * {@link com.keyfactor.util.crypto.algorithm.AlgorithmConstant}.KEYALGORITHM_...
     * @return the generated token data
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if user cannot be found
     * @throws UserDoesntFullfillEndEntityProfile if we add or edit a profile that doesn't match its end entity profile.
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws EjbcaException if an error occurred
     * @see #editUser(UserDataVOWS)
     */
    @SuppressWarnings("deprecation")
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/softTokenRequest")
	public KeyStore softTokenRequest(UserDataVOWS userData, String hardTokenSN, String keySpec, String keyAlg)
	throws CADoesntExistsException, AuthorizationDeniedException, NotFoundException, UserDoesntFullfillEndEntityProfile,
            ApprovalException, EjbcaException {
	    final IPatternLogger logger = TransactionLogger.getPatternLogger();
	    try {
	        log.debug("Soft token req for user '" + userData.getUsername() + "'.");
	        userData.setStatus(EndEntityConstants.STATUS_NEW);
	        userData.setClearPwd(true);
	    	final AuthenticationToken admin = getAdmin(false);
	    	logAdminName(admin,logger);

            final boolean createJKS = userData.getTokenType().equals(UserDataVOWS.TOKEN_TYPE_JKS);
            final byte[] encodedKeyStore = raMasterApiProxyBean.softTokenRequest(admin, userData, keySpec, keyAlg, createJKS);
            // Convert encoded KeyStore to the proper return type
	        final java.security.KeyStore ks;
	        if (createJKS) {
	        	ks = java.security.KeyStore.getInstance("JKS");
	        } else {
	            // BC PKCS12 uses 3DES for key protection and 40 bit RC2 for protecting the certificates
	        	ks = java.security.KeyStore.getInstance("PKCS12", "BC");
	        }
	        ks.load(new ByteArrayInputStream(encodedKeyStore), userData.getPassword().toCharArray());
            return new KeyStore(ks, userData.getPassword());
        } catch(CADoesntExistsException | AuthorizationDeniedException t ) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), t.toString());
            throw t;
        } catch (AuthStatusException e) {
			// Don't log a bad error for this (user wrong status)
            throw getEjbcaException(e, logger, ErrorCode.USER_WRONG_STATUS, Level.DEBUG);
		} catch (AuthLoginException e) {
            throw getEjbcaException(e, logger, ErrorCode.LOGIN_ERROR, Level.INFO);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException | CertificateException | IOException /*| CertificateSerialNumberException | IllegalNameException | InvalidKeySpecException | InvalidAlgorithmParameterException*/ | RuntimeException e) {
            throw getInternalException(e, logger);
        } catch (EndEntityProfileValidationException e) {
            throw new UserDoesntFullfillEndEntityProfile(e);
        } finally {
            logger.writeln();
            logger.flush();
        }
	}

    /**
     * Retrieves an SSH CA's public key in SSH .pub format
     *
     * Retrieving keys requires no authentication.
     *
     * @param caName the name of the CA
     * @return the CA's public key in SSH format, as a byte array.
     * @throws SshKeyException if the CA was not a SSH CA, or if there was an error in encoding the key.
     * @throws CADoesntExistsException if no CA by that name was found.
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getSshCaPublicKey")
    public byte[] getSshCaPublicKey(final String caName) throws SshKeyException, CADoesntExistsException {
        if(!CAFactory.INSTANCE.existsCaType(SshCa.CA_TYPE)) {
            throw new UnsupportedOperationException("SSH module does not exist on this instance of EJBCA.");
        } else {
            return raMasterApiProxyBean.getSshCaPublicKey(caName);
        }
    }

    /**
     * Retrieves the current certificate chain for a CA.
     *
     * <pre>
     * <b>Authorization requirements:</b>
     * - /administrator
     * - /ca/&lt;ca in question&gt;
     * </pre>
     *
     * <p>If the CA does not exist or authorization was denied on the local system,
     *     then the request will be forwarded to upstream peer systems (if any).</p>
     *
     * @param caName the unique name of the CA whose certificate chain should be returned
     * @return a list of X509 Certificates or CVC Certificates with the root certificate last, or an empty list if the CA's status is "Waiting for certificate response"
     * @throws AuthorizationDeniedException if the client does not fulfill the authorization requirements specified above
     * @throws CADoesntExistsException if the CA with the CA name given as input does not exist
     * @throws EjbcaException on internal errors, such as badly encoded certificate
     */
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getLastCAChain")
    public List<Certificate> getLastCAChain(String caName)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCAChain: "+ caName);
        }
        final List<Certificate> result = new ArrayList<>();
        final AuthenticationToken admin = getAdmin();
        final IPatternLogger logger = TransactionLogger.getPatternLogger();
        logAdminName(admin,logger);
        try {
            final Collection<CertificateWrapper> certificates = raMasterApiProxyBean.getLastCaChain(admin, caName);
            for (final CertificateWrapper certWrapper : certificates) {
                result.add(new Certificate(certWrapper.getCertificate()));
            }
        } catch (CertificateEncodingException | RuntimeException e) {
            throw getInternalException(e, logger);
        }
        finally {
            logger.writeln();
            logger.flush();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getLastCAChain: "+ caName);
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

    private static List<Certificate> convertCertificateCollectionToWsObjects(List<java.security.cert.Certificate> certificates)
            throws CertificateEncodingException {
        final List<Certificate> result = new ArrayList<>();
        for (java.security.cert.Certificate certificate : certificates) {
            result.add(new Certificate(certificate));
        }
        return result;
    }

    /**
     * Placeholder for removed method. Removed in EJBCA 7.1.0, when Hard Token support was dropped.
     *
     * @param hardTokenSN hard token sn
     * @param reason reason
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws NotFoundException if an object cannot be found in the database
     * @throws EjbcaException Always thrown with error code set to ErrorCode.INTERNAL_ERROR
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws AlreadyRevokedException if certificate was already revoked, or you tried to unrevoke a permanently revoked certificate
     * @deprecated Removed in EJBCA 7.1.0
     */
    @Deprecated
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/revokeToken")
    public void revokeToken(String hardTokenSN, int reason)
            throws NotFoundException, AlreadyRevokedException, ApprovalException, EjbcaException {
        throw makeHardTokenSupportRemovedException("revokeToken");
    }

    /**
     * Placeholder for removed method. Removed in EJBCA 7.1.0, when Hard Token support was dropped.
     *
     * @param userData user data
     * @param tokenRequests token requests
     * @param hardTokenData hard token data
     * @param overwriteExistingSN overwrite existing sn
     * @param revokePreviousCards revoke previous card
     * @return Hard Tokens are no longer supported. Always throws EjbcaException
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws HardTokenExistsException if hard token exists.
     * @throws UserDoesntFullfillEndEntityProfile if we add or edit a profile that doesn't match its end entity profile.
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws EjbcaException Always thrown with error code set to ErrorCode.INTERNAL_ERROR
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it won't throw it anymore.
     * @throws ApprovalRequestExecutionException if approval request execution failed.
     * @deprecated Removed in EJBCA 7.1.0
     */
    @Deprecated
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/genTokenCertificates")
    public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userData, List<org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS> tokenRequests,
            org.ejbca.core.protocol.ws.objects.HardTokenDataWS hardTokenData, boolean overwriteExistingSN, boolean revokePreviousCards)
            throws ApprovalException, EjbcaException {
        throw makeHardTokenSupportRemovedException("genTokenCertificates");
    }

    /**
     * Placeholder for removed method. Removed in EJBCA 7.1.0, when Hard Token support was dropped.
     *
     * @param hardTokenSN hard token sn
     * @return Hard Tokens are no longer supported. Always throws EjbcaException
     * @throws EjbcaException Always thrown with error code set to ErrorCode.INTERNAL_ERROR
     * @deprecated Removed in EJBCA 7.1.0
     */
    @Deprecated
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/existsHardToken")
    public boolean existsHardToken(String hardTokenSN) throws EjbcaException {
        throw makeHardTokenSupportRemovedException("existsHardToken");
    }

    /**
     * Placeholder for removed method. Removed in EJBCA 7.1.0, when Hard Token support was dropped.
     *
     * @param hardTokenSN hard token sn
     * @param viewPUKData c
     * @param onlyValidCertificates only valid certificates
     * @return Hard Tokens are no longer supported. Always throws EjbcaException
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws HardTokenDoesntExistsException if hard token doesn't exist
     * @throws NotFoundException if an object cannot be found in the database
     * @throws ApprovalException if there is already a request waiting for approval.
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it won't throw it anymore.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws ApprovalRequestExecutionException if approval request execution failed.
     * @throws EjbcaException Always thrown with error code set to ErrorCode.INTERNAL_ERROR
     * @deprecated Removed in EJBCA 7.1.0
     */
    @Deprecated
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getHardTokenData")
    public org.ejbca.core.protocol.ws.objects.HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates)
            throws NotFoundException, ApprovalException, EjbcaException {
        throw makeHardTokenSupportRemovedException("getHardTokenData");
    }

    /**
     * Placeholder for removed method. Removed in EJBCA 7.1.0, when Hard Token support was dropped.
     *
     * @param username username
     * @param viewPUKData overwriteExistingSN
     * @param onlyValidCertificates only valid certificates
     * @return Hard Tokens are no longer supported. Always throws EjbcaException
     * @throws CADoesntExistsException if a referenced CA does not exist
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @throws EjbcaException Always thrown with error code set to ErrorCode.INTERNAL_ERROR
     * @deprecated Removed in EJBCA 7.1.0
     */
    @Deprecated
    @WebMethod
    @Action(input="http://ws.protocol.core.ejbca.org/getHardTokenDatas")
    public List<org.ejbca.core.protocol.ws.objects.HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates)
            throws EjbcaException {
        throw makeHardTokenSupportRemovedException("getHardTokenDatas");
    }

    private EjbcaException makeHardTokenSupportRemovedException(final String methodName) {
        log.info("Method " + methodName + " was called, which is no longer supported since EJBCA 7.1.0. Returning EjbcaException with ErrorCode.INTERNAL_ERROR.");
        return new EjbcaException(ErrorCode.INTERNAL_ERROR, "Hard Token support has been removed since EJBCA 7.1.0. Method " + methodName + " is no longer supported.");
    }
}
