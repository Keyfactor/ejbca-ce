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

import java.security.Key;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
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

    public WebAuthenticationProviderSessionBean() { }

    /** Constructor for unit tests */
    protected WebAuthenticationProviderSessionBean(final CertificateStoreSessionLocal certificateStoreSession,
            final GlobalConfigurationSessionLocal globalConfigurationSession,
            final SecurityEventsLoggerSessionLocal securityEventsLoggerSession) {
        this.certificateStoreSession = certificateStoreSession;
        this.globalConfigurationSession = globalConfigurationSession;
        this.securityEventsLoggerSession = securityEventsLoggerSession;
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
    public AuthenticationToken authenticateUsingOAuthBearerToken(final String encodedOauthBearerToken) {
        try {
            String keyFingerprint = null;
            OAuthKeyInfo keyInfo = null;
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
                keyInfo = getJwtKey(signedJwt.getHeader().getKeyID());
                if (keyInfo == null) {
                    logAuthenticationFailure(intres.getLocalizedMessage(signedJwt.getHeader().getKeyID() != null ? "authentication.jwt.keyid_missing" : "authentication.jwt.default_keyid_not_configured"));
                    return null;
                }
                final byte[] keyBytes = keyInfo.getPublicKeyBytes();
                keyFingerprint = keyInfo.getKeyFingerprint();
                final Key key = KeyTools.getPublicKeyFromBytes(keyBytes);
                final JWSVerifier verifier = new DefaultJWSVerifierFactory().createJWSVerifier(signedJwt.getHeader(), key);
                if (!signedJwt.verify(verifier)) {
                    logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.invalid_signature", keyFingerprint));
                    return null;
                }
            } else {
                LOG.info("Received unsupported OAuth2 JWT type.");
                return null;
            }
            final JWTClaimsSet claims = jwt.getJWTClaimsSet();
            final Date expiry = claims.getExpirationTime();
            final Date now = new Date();
            final String subject = claims.getSubject();
            if (expiry != null && !now.before(new Date(expiry.getTime() + keyInfo.getSkewLimit()))) {
                logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.expired", subject, keyFingerprint));
                return null;
            }
            if (claims.getNotBeforeTime() != null && now.before(new Date(claims.getNotBeforeTime().getTime() - keyInfo.getSkewLimit()))) {
                logAuthenticationFailure(intres.getLocalizedMessage("authentication.jwt.not_yet_valid", subject, keyFingerprint));
                return null;
            }
            final OAuth2Principal principal = new OAuth2Principal(claims.getIssuer(), claims.getSubject(), claims.getAudience());
            return new OAuth2AuthenticationToken(principal, encodedOauthBearerToken, keyFingerprint);
        } catch (ParseException e) {
            LOG.info("Failed to parse OAuth2 JWT: " + e.getMessage(), e);
            return null;
        } catch (JOSEException e) {
            LOG.info("Configured not verify OAuth2 JWT signature: " + e.getMessage(), e);
            return null;
        }
    }

    private OAuthKeyInfo getJwtKey(final String keyId) {
        final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final Map<Integer,OAuthKeyInfo> availableKeys = globalConfig.getOauthKeys();
        if (keyId != null) {
            for (final OAuthKeyInfo key : availableKeys.values()) {
                if (keyId.equals(key.getKeyIdentifier())) {
                    return key;
                }
            }
            return null;
        } else {
            // Use default key
            // TODO ECA-9351
            return null;
        }
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
}
