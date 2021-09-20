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
package org.cesecore.authorization.user.matchvalues;

import java.util.Arrays;
import java.util.List;

import org.cesecore.authentication.tokens.OAuth2AuthenticationTokenMetaData;
import org.cesecore.authorization.user.AccessMatchType;

/**
 * Match values for OAuth2AuthenticationToken
 */
public enum OAuth2AccessMatchValue implements AccessMatchValue {
    /** Matches the "sub" (subject) claim */
    CLAIM_SUBJECT(1),
    /** Matches the "iss" (issuer) claim */
    CLAIM_ISSUER(2),
    /** Matches an "aud" (audience) claim */
    CLAIM_AUDIENCE(3),
    /** Matches the "oid" (object identifier) claim */
    CLAIM_OBJECTID(4),
    /** Match one of the entries in the "role" claim */
    CLAIM_ROLE(5),
    // NOTE: preferred_username, email, etc. should not be considered to be stable, according to the OpenID connect specification.
    // And according to Azure documentation, they MUST NOT be used for authorization decisions. See:
    // https://openid.net/specs/openid-connect-core-1_0.html
    // https://github.com/MicrosoftDocs/azure-docs/blob/master/articles/active-directory/develop/id-tokens.md

//  Possible future extension, to allow for arbitrary claims, and to require multiple different claims
//    /** An JSON string with claims */
//    JSON_CLAIMS()
    ;

    private final int numericValue;

    private OAuth2AccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public boolean isDefaultValue() {
        return numericValue == CLAIM_SUBJECT.numericValue;
    }

    @Override
    public String getTokenType() {
        return OAuth2AuthenticationTokenMetaData.TOKEN_TYPE;
    }

    @Override
    public boolean isIssuedByCa() {
        return false;
    }

    @Override
    public boolean isIssuedByOauthProvider() {
        return true;
    }

    @Override
    public List<AccessMatchType> getAvailableAccessMatchTypes() {
        return Arrays.asList(AccessMatchType.TYPE_EQUALCASE);
    }

    @Override
    public String normalizeMatchValue(final String value) {
        return value; // no normalization
    }
}
