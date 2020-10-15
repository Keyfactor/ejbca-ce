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
package org.ejbca.core.ejb.authentication.web;

import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.isNull;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.OAuth2AuthenticationToken;
import org.cesecore.authentication.tokens.OAuth2Principal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.easymock.EasyMock;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.log.LogConstants;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.nimbusds.jose.util.Base64URL;

/**
 * Test of {@link WebAuthenticationProviderSessionBean}. See also WebAuthenticationProviderSessionBeanTest
 */
public class WebAuthenticationProviderSessionUnitTest {

    private static final Logger log = Logger.getLogger(WebAuthenticationProviderSessionUnitTest.class);
    // For checking audit logging
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" + 
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyiRvfMhXb1nLE+bQ8Dtg\n" + 
            "P/YFPm6nesE+hNeSlxXQbdRI/Vd6djyynnptBVxZIvRmuax/zQRNqdK+FsoZKQGJ\n" + 
            "978PuBhFoLsgCyccrqCEfO2kZp9atXFYoctgXW339Kj2bF5zRhYlSqCD/vBKcjCd\n" + 
            "d6q0myEseplcPUzZXWbKHsdP4irjNRS3SwjKjetDBZ6FquAb5jXlSFH9JUx8iRYF\n" + 
            "Bv4F3TDWC1NHFp3fpLovUjcZama6nrY7VQfnsLFY2YKPahQqikd4NSny2wmnonnw\n" + 
            "Vyos88Ylt//DlzVgijMOvDE4TKF81g4qbd7x8B/JpPxdBk3gXdgJk8+S+scOqfPX\n" + 
            "swIDAQAB\n" + 
            "-----END PUBLIC KEY-----\n";

    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" + 
            "MIIEpAIBAAKCAQEAyiRvfMhXb1nLE+bQ8DtgP/YFPm6nesE+hNeSlxXQbdRI/Vd6\n" + 
            "djyynnptBVxZIvRmuax/zQRNqdK+FsoZKQGJ978PuBhFoLsgCyccrqCEfO2kZp9a\n" + 
            "tXFYoctgXW339Kj2bF5zRhYlSqCD/vBKcjCdd6q0myEseplcPUzZXWbKHsdP4irj\n" + 
            "NRS3SwjKjetDBZ6FquAb5jXlSFH9JUx8iRYFBv4F3TDWC1NHFp3fpLovUjcZama6\n" + 
            "nrY7VQfnsLFY2YKPahQqikd4NSny2wmnonnwVyos88Ylt//DlzVgijMOvDE4TKF8\n" + 
            "1g4qbd7x8B/JpPxdBk3gXdgJk8+S+scOqfPXswIDAQABAoIBAQCeUCDcqo8Hz1xj\n" + 
            "7s7OhsIf9c8vkTwrwLL1GVxeZaBClBLCD0QC3BDMW3eMzkGlRaI6YqYI7AjjKwDj\n" + 
            "Gk7QNbtXQ9TMyn2ln0g+U9h7z41Txk6ObNl+5xGSTZTgN2MNw1KTlvlS978nDkWy\n" + 
            "YYD8o6R/9zrRkA6kyf1aqRhHtVww82WFbB5DV5yqIxz8wLU7ugzs/2iiV/aqq5cJ\n" + 
            "WRHFhiqmtA+88fAdrCTq0DWif6Chf5SYrY2pirTBHFpqVWs/3cq86eoVFpMYlMCY\n" + 
            "AxroxHjLmJM0sSB6wCDfJEMgBtMgIm6Boh4xSM6KcOZitcj51dvM3Deh5BhJnNdq\n" + 
            "oAtod/ThAoGBAO+9vXFYUBa9Yn+d1PBXc4X0iNMEh7jdGdqD6QRrBOwb2sYEishz\n" + 
            "kaIZSM0U8yoApS5vDxGTYSdUm53rX5/d4tfW2BNjomV2dD6u3RyhXBz84aSHeWX8\n" + 
            "p02ZzDjHUxR7CZ2ZmbsN1Ite+AKb/zwDt5KaiVSCyNwlhxwKJ454PecDAoGBANfZ\n" + 
            "7JN07SBtaSD6Q3N7V7WvhrQzm/GU477+LYhLWtGPp/KylvSKuPK3jL3/cvk+Mm3l\n" + 
            "UkCF5sZ3A2fbkymP7koHQPGDqSrKH0qAN4+g5zuy0R6+bKdpqkUVuESLG8YCYfOM\n" + 
            "cqhc+JvD4ECYEBNgBsBcwUHLOtu0eSss76bbEFWRAoGAZtj8M2rSeN7oKZ05I54w\n" + 
            "pg/gvr4bx3e6xp5+UXHj27KbaQW70ACcQnEcZTaOlr9OHZxxV3XlYO0QEXBPRpL2\n" + 
            "5Od7LN46ZdKqTdXQb57dmGX4GxAvSUxZLZZEITuJbajW2DBz3eYx/1RPizcHCOUD\n" + 
            "VLZNId81chP7YVEN5TW6QKcCgYEAjeF69foXnAcO4VRfXdsnbg9wVabOzF73zKU6\n" + 
            "vKn7imAJHyhwvVEp/LDV3FW690YA0+e2xx688JtuK6hS9TDciuB1ucq3OZ8eLlRV\n" + 
            "MR2soLsLZk/5D5oPB9YdB0EBAoiyZepdu3lRGOIJ16ucdX/bMDpH9b1mdOAN/WlO\n" + 
            "Jbk85WECgYBMV1RqyFI7eCg5h6F934mU2h/cq9HdYLFX+vvEG+CwYviJF6p5R44u\n" + 
            "NAoG0QxYULgcHIscLySYau4lHRgv7hAOrhY+UsJ3MnI97Gea4Gvvu4e5F13fzjlp\n" + 
            "GmQnXm8ydcaDNPM6Xp7nMMjNAwXB0H9z9DFKejPFT1aDmnHY+1X+SA==\n" + 
            "-----END PRIVATE KEY-----\n";

    private static String pubKeyFingerprint;
    private static byte[] pubKeyBytes;
    private static PrivateKey privKey;
    
    private WebAuthenticationProviderSessionBean webAuthenticationProviderSession;
    private CertificateStoreSessionLocal certStoreSessionMock = EasyMock.createStrictMock(CertificateStoreSessionLocal.class);
    private GlobalConfigurationSessionLocal globalConfigurationSessionMock = EasyMock.createStrictMock(GlobalConfigurationSessionLocal.class);
    private SecurityEventsLoggerSessionLocal securityEventsSessionMock = EasyMock.createStrictMock(SecurityEventsLoggerSessionLocal.class);

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException, InvalidKeySpecException {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // Public key
        pubKeyBytes = KeyTools.getBytesFromPEM(PUBLIC_KEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);
        pubKeyFingerprint = Base64.toBase64String(CertTools.generateSHA256Fingerprint(pubKeyBytes));
        // Private key
        final byte[] privKeyBytes = KeyTools.getBytesFromPEM(PRIVATE_KEY, CertTools.BEGIN_PRIVATE_KEY, CertTools.END_PRIVATE_KEY);
        final PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privKey = keyFactory.generatePrivate(pkKeySpec);
    }

    @Before
    public void before() {
        EasyMock.reset(certStoreSessionMock, globalConfigurationSessionMock, securityEventsSessionMock);
        webAuthenticationProviderSession = new WebAuthenticationProviderSessionBean(certStoreSessionMock, globalConfigurationSessionMock, securityEventsSessionMock);
    }

    @Test
    public void blankToken() {
        log.trace(">blankToken");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(""));
        log.trace("<blankToken");
    }

    @Test
    public void missingDots() {
        log.trace(">missingDots");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken("AAAA"));
        log.trace("<missingDots");
    }

    @Test
    public void malformedBase64() {
        log.trace(">malformedBase64");
        // The token format is: JOSE-Header.Payload.Signature, and each part should be base64url encoded
        // See RFC-7519 section 3.1, https://tools.ietf.org/html/rfc7519#section-3.1
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken("åäö.åäö.åäö"));
        log.trace("<malformedBase64");
    }

    @Test
    public void nonJsonToken() {
        log.trace(">nonJsonToken");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken("AAAA.AAAA.AAAA"));
        log.trace("<nonJsonToken");
    }
    
    private byte[] sign(final byte[] toBeSigned, final PrivateKey key) {
        try {
            return KeyTools.signData(key, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, toBeSigned);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }
    
    private String encodeToken(final String headerJson, final String payloadJson) {
        return encodeToken(headerJson, payloadJson, null);
    }
    
    private String encodeToken(final String headerJson, final String payloadJson, final PrivateKey key) {
        final StringBuilder sb = new StringBuilder();
        sb.append(Base64URL.encode(headerJson).toString());
        sb.append('.');
        sb.append(Base64URL.encode(payloadJson).toString());
        if (key != null) {
            final byte[] signature = sign(sb.toString().getBytes(StandardCharsets.US_ASCII), key);
            sb.append('.');
            sb.append(Base64URL.encode(signature).toString());
        } else {
            sb.append('.');
        }
        return sb.toString();
    }

    private String timestampFromNow(final long offset) {
        return String.valueOf((System.currentTimeMillis() + offset) / 1000);
    }
    
    @Test
    public void nonJwtToken() {
        log.trace(">nonJwtToken");
        final String token = encodeToken("{\"data\":123}", "{\"data\":123}");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        log.trace("<nonJwtToken");
    }

    @Test
    public void unsignedToken() {
        log.trace(">unsignedToken");
        final String token = encodeToken("{\"alg\":\"none\"}", "{\"sub\":\"johndoe\"}");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        log.trace("<unsignedToken");
    }

    @Test
    public void missingSignature() {
        log.trace(">missingSignature");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}");
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock);
        log.trace("<missingSignature");
    }

    @Test
    public void malformedSignature() {
        log.trace(">malformedSignature");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}") + "AAAA"; // last part is signature
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock);
        log.trace("<malformedSignature");
    }

    @Test
    public void unknownSignatureAlgorithm() {
        log.trace(">unknownSignatureAlgorithm");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String token = encodeToken("{\"alg\":\"XX\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}") + "AAAA"; // last part is signature
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock);
        log.trace("<unknownSignatureAlgorithm");
    }

    @Test
    public void expiredToken() {
        log.trace(">expiredToken");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        expectAuditLog("authentication.jwt.expired", "johndoe", pubKeyFingerprint);
        replay(globalConfigurationSessionMock, securityEventsSessionMock);
        final String timestamp = timestampFromNow(-60*60*1000); // 1 hour old
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\",\"exp\":" + timestamp + "}", privKey);
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock, securityEventsSessionMock);
        log.trace("<expiredToken");
    }

    @Test
    public void notYetValidToken() {
        log.trace(">notYetValidToken");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        expectAuditLog("authentication.jwt.not_yet_valid", "johndoe", pubKeyFingerprint);
        replay(globalConfigurationSessionMock, securityEventsSessionMock);
        final String timestamp = timestampFromNow(60*60*1000); // 1 hour ahead
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\",\"nbf\":" + timestamp + "}", privKey);
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock, securityEventsSessionMock);
        log.trace("<notYetValidToken");
    }

    @Test
    public void tamperedWithContents() {
        log.trace(">tamperedWithContents");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        expectAuditLog("authentication.jwt.invalid_signature", pubKeyFingerprint);
        replay(globalConfigurationSessionMock, securityEventsSessionMock);
        final String originalToken = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}", privKey);
        // Change the payload
        final String newPayload = Base64URL.encode("{\"sub\":\"janedoe\"}").toString(); // johndoe -> janedoe
        final String[] pieces = originalToken.split("\\.");
        final String token = pieces[0] + "." + newPayload + "." + pieces[2];
        assertNull("Authentication should fail", webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token));
        verify(globalConfigurationSessionMock, securityEventsSessionMock);
        log.trace("<tamperedWithContents");
    }

    private void expectAuditLog(final String messageKey, final Object... params) {
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", intres.getLocalizedMessage(messageKey, params));
        securityEventsSessionMock.log(same(EventTypes.AUTHENTICATION), same(EventStatus.FAILURE), same(EjbcaModuleTypes.ADMINWEB),
                same(EjbcaServiceTypes.EJBCA), same(LogConstants.NO_AUTHENTICATION_TOKEN), isNull(), isNull(), isNull(), eq(details));
        expectLastCall();
    }

    private void expectConfigRead(final OAuthKeyInfo... keyInfos) {
        final GlobalConfiguration globalConfig = new GlobalConfiguration();
        for (final OAuthKeyInfo keyInfo : keyInfos) {
            globalConfig.addOauthKey(keyInfo);
        }
        expect(globalConfigurationSessionMock.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).andReturn(globalConfig);
    }

    @Ignore("Configuration of a 'default key' is not yet implemented.") // TODO enable and update test when ECA-9351 is done
    @Test
    public void successfulRsaDefaultKey() {
        log.trace(">successfulRsaDefaultKey");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String token = encodeToken("{\"alg\":\"RS256\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}", privKey);
        final OAuth2AuthenticationToken admin = (OAuth2AuthenticationToken) webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token);
        verify(globalConfigurationSessionMock);
        assertNotNull("Authentication should succeed", admin);
        final OAuth2Principal principal = admin.getClaims();
        assertNotNull("Should have a Principal object", principal);
        assertEquals("Incorrect subject claim", "johndoe", principal.getSubject());
        assertNull("Unexpected issuer claim", principal.getIssuer());
        assertTrue("Unexpected audience claim", principal.getAudience().isEmpty());
        assertEquals("Incorrect public key fingerprint", pubKeyFingerprint, admin.getPublicKeyBase64Fingerprint());
        log.trace("<successfulRsaDefaultKey");
    }

    @Test
    public void successfulRsaWithKeyId() {
        log.trace(">successfulRsaWithKeyId");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}", "{\"sub\":\"johndoe\"}", privKey);
        final OAuth2AuthenticationToken admin = (OAuth2AuthenticationToken) webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token);
        verify(globalConfigurationSessionMock);
        assertNotNull("Authentication should succeed", admin);
        final OAuth2Principal principal = admin.getClaims();
        assertNotNull("Should have a Principal object", principal);
        assertEquals("Incorrect subject claim", "johndoe", principal.getSubject());
        assertNull("Unexpected issuer claim", principal.getIssuer());
        assertTrue("Unexpected audience claim", principal.getAudience().isEmpty());
        assertEquals("Incorrect public key fingerprint", pubKeyFingerprint, admin.getPublicKeyBase64Fingerprint());
        log.trace("<successfulRsaWithKeyId");
    }

    /** Tests with a token with all supported attributes. */
    @Test
    public void successfulComplexToken() {
        log.trace(">successfulComplexToken");
        expectConfigRead(new OAuthKeyInfo("key1", pubKeyBytes, 1000));
        replay(globalConfigurationSessionMock);
        final String expiry = timestampFromNow(60*60*1000); // 1 hour ahead
        final String notBefore = timestampFromNow(-60*60*1000); // 1 hour old
        final String token = encodeToken("{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}",
                "{\"aud\":[\"admins\"],\"exp\":" + expiry + ",\"iss\":\"issuer1\",\"nbf\":" + notBefore + ",\"sub\":\"johndoe\"}", privKey);
        final OAuth2AuthenticationToken admin = (OAuth2AuthenticationToken) webAuthenticationProviderSession.authenticateUsingOAuthBearerToken(token);
        verify(globalConfigurationSessionMock);
        assertNotNull("Authentication should succeed", admin);
        final OAuth2Principal principal = admin.getClaims();
        assertNotNull("Should have a Principal object", principal);
        assertEquals("Incorrect subject claim", "johndoe", principal.getSubject());
        assertEquals("Incorrect issuer claim", "issuer1", principal.getIssuer());
        assertEquals("Incorrect audience claim", Collections.singletonList("admins"), principal.getAudience());
        assertEquals("Incorrect public key fingerprint", pubKeyFingerprint, admin.getPublicKeyBase64Fingerprint());
        log.trace("<successfulComplexToken");
    }
}
