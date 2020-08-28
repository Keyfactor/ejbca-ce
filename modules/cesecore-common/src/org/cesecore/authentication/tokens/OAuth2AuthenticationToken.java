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
package org.cesecore.authentication.tokens;

import java.util.Collections;
import java.util.Objects;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.OAuth2AccessMatchValue;

/**
 * Authentication token for OAuth2 with JWT
 */
public class OAuth2AuthenticationToken extends NestableAuthenticationToken {

    public static final OAuth2AuthenticationTokenMetaData metaData = new OAuth2AuthenticationTokenMetaData();

    private static final Logger log = Logger.getLogger(OAuth2AuthenticationToken.class);
    private static final long serialVersionUID = 1L; 

    private final OAuth2Principal principal;
    private final String encodedToken;
    private final String base64Fingerprint;

    /**
     * Creates an OAuth2AuthenticationToken. No validation is performed that the token is valid, or that
     * the claims in the principal matches the one the in token.
     *
     * @param principal Principal containing claims (issuer, subject and audience)
     * @param encodedToken Encoded JWT token. For an example see <a href="https://tools.ietf.org/html/rfc7519#section-3.1">RFC-7519 section 3.1</a>.
     * @param base64Fingerprint Base64 encoded SHA-256 fingerprint of public key that was used to verify the JWT.
     */
    public OAuth2AuthenticationToken(final OAuth2Principal principal, final String encodedToken, final String base64Fingerprint) {
        super(Collections.singleton(principal), Collections.singleton(encodedToken));
        Objects.requireNonNull(principal, "principal may not be null");
        Objects.requireNonNull(encodedToken, "encodedToken may not be null");
        this.principal = principal;
        this.encodedToken = encodedToken;
        this.base64Fingerprint = base64Fingerprint;
    }

    @Override
    public boolean matches(final AccessUserAspect accessUser) throws AuthenticationFailedException {
        // Protect against spoofing by checking if this token was created locally
        if (!super.isCreatedInThisJvm()) {
            return false;
        } 
        if (!StringUtils.equals(getMetaData().getTokenType(), accessUser.getTokenType())) {
            log.debug("Role token type does not match.");
            return false;
        }
        final OAuth2AccessMatchValue matchWith = (OAuth2AccessMatchValue) getMatchValueFromDatabaseValue(accessUser.getMatchWith());
        final String value = accessUser.getMatchValue();
        switch (matchWith) {
        case CLAIM_ISSUER:
            return value.equals(principal.getIssuer());
        case CLAIM_SUBJECT:
            return value.equals(principal.getSubject());
        case CLAIM_AUDIENCE:
            return principal.getAudience() != null && principal.getAudience().contains(value);
// Possible future extension, to allow arbitrary claims (pseudo-code)
//      case JSON_CLAIMS:
//          for (final Entry<String,String> claim : jsonToMap(value)) {
//              if (!claim.getValue().equals(principal.getClaim(claim.getKey()))) {
//                  return false;
//              }
//          }
//          return true;
        default:
            throw new IllegalStateException("Unexpected match value");
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final OAuth2AuthenticationToken other = (OAuth2AuthenticationToken) obj;
        return StringUtils.equals(other.encodedToken, encodedToken);
    }

    @Override
    public int hashCode() {
        return encodedToken.hashCode();
    }

    @Override
    protected String generateUniqueId() {
        return generateUniqueId(super.isCreatedInThisJvm(), encodedToken) + ";" + super.generateUniqueId();
    }

    @Override
    public AuthenticationTokenMetaData getMetaData() {
        return metaData;
    }

    @Override
    public int getPreferredMatchKey() {
        return OAuth2AccessMatchValue.CLAIM_SUBJECT.getNumericValue();
    }

    @Override
    public String getPreferredMatchValue() {
        return principal.getSubject();
    }

    public OAuth2Principal getClaims() {
        return principal;
    }

    public String getPublicKeyBase64Fingerprint() {
        return base64Fingerprint;
    }
}
