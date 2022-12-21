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
package org.ejbca.core.ejb.authentication.web;

import java.io.IOException;

import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.KeyBindingFinder;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthGrantResponseInfo;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.oauth.OAuthPublicKey;
import org.cesecore.authentication.oauth.OauthRequestHelper;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.OAuth2Principal.Builder;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.KeyBindingNotFoundException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.log.LogConstants;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 *
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "WebAuthenticationProviderSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class WebAuthenticationProviderSessionBean implements WebAuthenticationProviderSessionLocal {

    private static final long serialVersionUID = 1524951666783567785L;

    private final static Logger LOG = Logger.getLogger(WebAuthenticationProviderSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindings;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoToken;

    private boolean allowBlankAudience = false;

    public WebAuthenticationProviderSessionBean() { }

    /** Constructor for unit tests */
    protected WebAuthenticationProviderSessionBean(final CertificateStoreSessionLocal certificateStoreSession,
            final GlobalConfigurationSessionLocal globalConfigurationSession,
            final SecurityEventsLoggerSessionLocal securityEventsLoggerSession) {
        this.certificateStoreSession = certificateStoreSession;
        this.globalConfigurationSession = globalConfigurationSession;
        this.securityEventsLoggerSession = securityEventsLoggerSession;
    }
    
    /**
     * OAuth audience ('aud') claim checking was not enforced until 7.8.0.  Allow a blank Audience value in the OAuth configuration to match any Bearer token until 
     * the database is post-upgraded to 7.8.0.  After that, it is expected that all OAuth provider configurations will have a configured Audience value and that Bearer 
     * token 'aud' claims will match that value to be considered valid.
     */
    @PostConstruct
    public void initializeAudienceCheck() {
        GlobalUpgradeConfiguration upgradeConfiguration = (GlobalUpgradeConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        allowBlankAudience = StringTools.isLesserThan(upgradeConfiguration.getPostUpgradedToVersion(), "7.8.0");
        if (isAllowBlankAudience()) {
            LOG.debug("Database not post-upgraded to 7.8.0 yet.  Allowing OAuth logins without checking 'aud' claim.");
        }
    }

    @Override
    public X509CertificateAuthenticationToken authenticateUsingClientCertificate(final X509Certificate x509Certificate) {
        return (X509CertificateAuthenticationToken) authenticate(new AuthenticationSubject(null, new HashSet<>( Arrays.asList(new X509Certificate[]{ x509Certificate }))));
    }

    @Override
    public PublicAccessAuthenticationToken authenticateUsingNothing(final String principal, final boolean confidentialTransport) {
        return new PublicAccessAuthenticationToken(principal, confidentialTransport);
    }

    @Override
    public AuthenticationToken authenticateUsingOAuthBearerToken(final OAuthConfiguration oauthConfiguration, final String encodedOauthBearerToken) throws TokenExpiredException {
        try {
            String keyFingerprint = null;
            OAuthKeyInfo keyInfo = null;
            if (oauthConfiguration == null || MapUtils.isEmpty(oauthConfiguration.getOauthKeys())) {
                LOG.info(oauthConfiguration == null ? "Failed to get OAuth configuration. If using peers, the CA version may be too old." :
                        "Cannot authenticate with OAuth because no providers are available");
                return null;
            }
            final JWT jwt = JWTParser.parse(encodedOauthBearerToken);
            if (jwt instanceof PlainJWT) {
                LOG.info("Not accepting unsigned OAuth2 JWT, which is insecure.");
                return null;
            } else if (jwt instanceof EncryptedJWT) {
                LOG.info("Received encrypted OAuth2 JWT, which is unsupported.");
                return null;
            } else if (jwt instanceof SignedJWT) {
                final SignedJWT signedJwt = (SignedJWT) jwt;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signed JWT has key ID: " + signedJwt.getHeader().getKeyID());
                }
                keyInfo = getJwtKey(oauthConfiguration, signedJwt.getHeader().getKeyID());
                if (keyInfo == null) {
                    logAuthenticationFailure(intres.getLocalizedMessage(signedJwt.getHeader().getKeyID() != null ? "authentication.jwt.keyid_missing" : "authentication.jwt.default_keyid_not_configured"));
                    return null;
                }
                OAuthPublicKey oAuthPublicKey = keyInfo.getKeys().get(signedJwt.getHeader().getKeyID());
                if (oAuthPublicKey != null) {
                    // Default provider (Key ID does not match)
                    if (verifyJwt(oAuthPublicKey, signedJwt)) {
                        keyFingerprint = oAuthPublicKey.getKeyFingerprint();
                    } else {
                        logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.invalid_signature", oAuthPublicKey.getKeyFingerprint()));
                        return null;
                    }
                } else {
                    if (keyInfo.getKeys().isEmpty()) {
                        logAuthenticationFailure(intres.getLocalizedMessage(signedJwt.getHeader().getKeyID() != null ? "authentication.jwt.keyid_missing" : "authentication.jwt.default_keyid_not_configured"));
                        return null;
                    } else {
                        for (OAuthPublicKey key : keyInfo.getKeys().values()) {
                            if (verifyJwt(key, signedJwt)) {
                                keyFingerprint = key.getKeyFingerprint();
                                break;
                            }
                        }
                        if (keyFingerprint == null) {
                            logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.invalid_signature_provider", keyInfo.getLabel()));
                            return null;
                        }
                    }
                }
            } else {
                LOG.info("Received unsupported OAuth2 JWT type.");
                return null;
            }
            final JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT Claims:" + claims);
            }
            
            // token `audience` (generally an identifier for this EJBCA application) needs to match the configured value
            if (!keyInfo.isAudienceCheckDisabled()) {
                final String expectedAudience = keyInfo.getAudience();
                if (StringUtils.isBlank(expectedAudience)) {
                    if (isAllowBlankAudience()) {
                        LOG.warn("Empty audience setting in OAuth configuration " + keyInfo.getLabel()
                                + ".  This is supported for recent upgrades from versions before 7.8.0, but a value should be set IMMEDIATELY.");
                    } else {
                        LOG.error("Configuration error: blank OAuth audience setting found.  Failing OAuth login");
                        return null;
                    }
                } else if (claims.getAudience() == null) {
                    LOG.warn("No audience claim in JWT.  Can't confirm validity.");
                    return null;
                } else if (!claims.getAudience().contains(expectedAudience)) {
                    logAuthenticationFailure(
                            intres.getLocalizedMessage("authentication.jwt.audience_mismatch", expectedAudience, claims.getAudience()));
                    return null;
                }
            }
            
            final Date expiry = claims.getExpirationTime();
            final Date now = new Date();
            final String subject = keyInfo.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_AZURE) ?
                    claims.getStringClaim("oid") : claims.getSubject();
            if (expiry != null && !now.before(new Date(expiry.getTime() + keyInfo.getSkewLimit()))) {
                LOG.info(intres.getLocalizedMessage("authentication.jwt.expired", subject, keyFingerprint));
                throw new TokenExpiredException("Token expired");
            }
            if (claims.getNotBeforeTime() != null && now.before(new Date(claims.getNotBeforeTime().getTime() - keyInfo.getSkewLimit()))) {
                logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.not_yet_valid", subject, keyFingerprint));
                return null;
            }
            final OAuth2Principal principal = createOauthPrincipal(claims, keyInfo);
            return new OAuth2AuthenticationToken(principal, encodedOauthBearerToken, keyFingerprint, keyInfo.getLabel());
        } catch (ParseException e) {
            LOG.info("Failed to parse OAuth2 JWT: " + e.getMessage(), e);
            return null;
        } catch (JOSEException e) {
            LOG.info("Configured not verify OAuth2 JWT signature: " + e.getMessage(), e);
            return null;
        }
    }

    private OAuth2Principal createOauthPrincipal(final JWTClaimsSet claims, OAuthKeyInfo keyInfo) {
        final Builder oauthBuilder = OAuth2Principal.builder()
                .setOauthProviderId(keyInfo.getInternalId())
                .setIssuer(claims.getIssuer())
                .setSubject(claims.getSubject())
                .setOid(safeGetClaim(claims, "oid"))
                .setAudience(claims.getAudience())
                .setPreferredUsername(safeGetClaim(claims, "preferred_username"))
                .setName(safeGetClaim(claims, "name"))
                .setEmail(safeGetClaim(claims, "email"))
                .setEmailVerified(safeGetBooleanClaim(claims, "email_verified"));
        
        // add Roles if they exist in the JWT and are of the expected type.  All this type checking may be overly paranoid,
        // but this is an external value used in authentication, and there's no schema for JSON
        if (claims.getClaims().containsKey("roles")) {
            final Object rolesClaimObject = claims.getClaim("roles");
            if (rolesClaimObject instanceof Collection<?>) {
                ((Collection<?>) rolesClaimObject).forEach(r -> {
                    if (r instanceof String) {
                        oauthBuilder.addRole((String) r);
                    }
                });
            }
            else {
                LOG.debug("unexpected type of 'roles' claim: " + rolesClaimObject.getClass());
            }
        }
        
        return oauthBuilder.build();
    }

    private String safeGetClaim(final JWTClaimsSet claims, final String claimName) {
        try {
            return claims.getStringClaim(claimName);
        } catch (ParseException e) {
            return null;
        }
    }

    private boolean safeGetBooleanClaim(final JWTClaimsSet claims, final String claimName) {
        try {
            return BooleanUtils.isTrue(claims.getBooleanClaim(claimName));
        } catch (ParseException e) {
            return false;
        }
    }

    private boolean verifyJwt(OAuthPublicKey oAuthPublicKey, SignedJWT signedJwt) throws JOSEException {
        final byte[] keyBytes = oAuthPublicKey.getPublicKeyBytes();
        final Key key = KeyTools.getPublicKeyFromBytes(keyBytes);
        final JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(signedJwt.getHeader(), key);
        return signedJwt.verify(verifier);
    }

    @Override
    public OAuthGrantResponseInfo refreshOAuthBearerToken(final OAuthConfiguration oauthConfiguration, final String encodedOauthBearerToken, final String refreshToken) {
        OAuthGrantResponseInfo oAuthGrantResponseInfo = null;
        try {
            OAuthKeyInfo keyInfo;
            final JWT jwt = JWTParser.parse(encodedOauthBearerToken);
            if (jwt instanceof PlainJWT) {
                LOG.info("Not accepting unsigned OAuth2 JWT, which is insecure.");
                return null;
            } else if (jwt instanceof EncryptedJWT) {
                LOG.info("Received encrypted OAuth2 JWT, which is unsupported.");
                return null;
            } else if (jwt instanceof SignedJWT) {
                final SignedJWT signedJwt = (SignedJWT) jwt;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Signed JWT has key ID: " + signedJwt.getHeader().getKeyID());
                }
                keyInfo = getJwtKey(oauthConfiguration, signedJwt.getHeader().getKeyID());
                if (keyInfo == null) {
                    logAuthenticationFailure(intres.getLocalizedMessage(signedJwt.getHeader().getKeyID() != null ? "authentication.jwt.keyid_missing" : "authentication.jwt.default_keyid_not_configured"));
                    return null;
                }
                String redirectUrl = getBaseUrl();
                OauthRequestHelper oauthRequestHelper = new OauthRequestHelper(new KeyBindingFinder(
                        internalKeyBindings, certificateStoreSession, cryptoToken));
                oAuthGrantResponseInfo = oauthRequestHelper.sendRefreshTokenRequest(refreshToken, keyInfo, redirectUrl);
            }
        } catch (ParseException e) {
            LOG.info("Failed to parse OAuth2 JWT: " + e.getMessage(), e);
            return null;
        } catch (IOException | KeyBindingNotFoundException | CryptoTokenOfflineException e) {
            LOG.info("Failed to refresh token: " + e.getMessage(), e);
            return null;
        }
        return oAuthGrantResponseInfo;
    }

    private OAuthKeyInfo getJwtKey(final OAuthConfiguration oauthConfiguration, final String keyId) {
        if (oauthConfiguration != null) {
            final Map<String,OAuthKeyInfo> availableKeys = oauthConfiguration.getOauthKeys();
            if (keyId != null) {
                for (final OAuthKeyInfo oAuthKeyInfo : availableKeys.values()) {
                    if (oAuthKeyInfo.getAllKeyIdentifiers() != null && oAuthKeyInfo.getAllKeyIdentifiers().contains(keyId)) {
                        return oAuthKeyInfo;
                    }
                }
            } else {
                 return oauthConfiguration.getDefaultOauthKey();
            }
        }
        return null;
    }

    /**
     * Performs client certificate authentication for a subject. This requires:
     * - An AuthenticationSubject containing a Set<X509Certificate>, where there should be only one certificate 
     *   being the administrators client certificate.
     * If the admin certificate is required to be in the database (properties configuration option) it is
     * verified that the certificate is present in the database and that it is not revoked.
     * 
     * @param subject an AuthenticationSubject containing a Set<X509Certificate> of credentials, the set must contain one certificate which is the admin client certificate.
     * @return an AuthenticationToken if the subject was authenticated, null otherwise.
     */
    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {
        @SuppressWarnings("unchecked")
        final Set<X509Certificate> certs = (Set<X509Certificate>) subject.getCredentials();
        if (certs.size() != 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("certificateArray contains "+certs.size()+" certificates, instead of 1 that is required.");
            }
            return null;
        } else {
            final X509Certificate certificate = certs.iterator().next();
            // Check Validity
            try {
                certificate.checkValidity();
            } catch (Exception e) {
                logAuthenticationFailure(intres.getLocalizedMessage("authentication.certexpired", CertTools.getSubjectDN(certificate), CertTools.getNotAfter(certificate).toString()));
            	return null;
            }
            // Find out if this is a certificate present in the local database (even if we don't require a cert to be present there we still want to allow a mix)
            // Database integrity protection verification not performed running this query
            final int status = certificateStoreSession.getFirstStatusByIssuerAndSerno(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate));
            if (status != -1) {
                // The certificate is present in the database.
                if (!(status == CertificateConstants.CERT_ACTIVE || status == CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION)) {
                    // The certificate is neither active, nor active (but user is notified of coming revocation)
                    logAuthenticationFailure(intres.getLocalizedMessage("authentication.revokedormissing", CertTools.getSubjectDN(certificate)));
                    return null;
                }
            } else {
                // The certificate is not present in the database.
                if (WebConfiguration.getRequireAdminCertificateInDatabase()) {
                    logAuthenticationFailure(intres.getLocalizedMessage("authentication.revokedormissing", CertTools.getSubjectDN(certificate)));
                    return null;
                }
                // TODO: We should check the certificate for CRL or OCSP tags and verify the certificate status
            }
            return new X509CertificateAuthenticationToken(certificate);
        }
    }

    private void logAuthenticationFailure(final String msg) {
        LOG.info(msg);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        securityEventsLoggerSession.log(EventTypes.AUTHENTICATION, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA, LogConstants.NO_AUTHENTICATION_TOKEN, null, null, null, details);
    }

    private String getBaseUrl(){
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        return globalConfiguration.getBaseUrl(
                "https",
                WebConfiguration.getHostName(),
                WebConfiguration.getPublicHttpsPort()
        ) + globalConfiguration.getAdminWebPath();
    }

    public boolean isAllowBlankAudience() {
        return allowBlankAudience;
    }
}
