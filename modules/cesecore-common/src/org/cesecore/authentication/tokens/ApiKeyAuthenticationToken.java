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

// SUBJECT FOR ECA-6877. LEAVE OUT UNTIL FINAL IMPLEMENTATION IS COMPLETE

package org.cesecore.authentication.tokens;

//import java.security.Principal;
//import java.util.HashSet;
//
//import org.apache.commons.lang.StringUtils;
//import org.cesecore.authentication.AuthenticationFailedException;
//import org.cesecore.authorization.user.AccessUserAspect;
//import org.cesecore.authorization.user.matchvalues.ApiKeyAccessMatchValue;
//import org.cesecore.keys.util.KeyTools;
//
///**
// * TODO Not done at all
// * @version $Id$
// *
// */
//public class ApiKeyAuthenticationToken extends AuthenticationToken {
//
//    private static final ApiKeyAuthenticationTokenMetaData metaData = new ApiKeyAuthenticationTokenMetaData();
//    
//    private static final long serialVersionUID = 1L;
//    
//    private final String apiKey;
//    private String apiKeyHash;
//
//    public ApiKeyAuthenticationToken(String apiKey) {
//        super(new HashSet<Principal>() {
//            private static final long serialVersionUID = 1L;
//            {
//                // TODO We need some way to identify each API key
//                add(new UsernamePrincipal("API Key"));
//            }
//        }, null);
//        this.apiKey = apiKey;
//        this.apiKeyHash = generateSha256Hash(apiKey);
//    }
//
//    @Override
//    public boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException {
//        if (StringUtils.isEmpty(apiKeyHash)) {
//            return false;
//        }
//        if (matchTokenType(accessUser.getTokenType()) && accessUser.getMatchValue().equals(apiKeyHash)) {
//            return true;
//        }
//        return false;
//    }
//
//    @Override
//    public boolean equals(Object obj) {
//        if (this == obj)
//            return true;
//        if (obj == null)
//            return false;
//        if (getClass() != obj.getClass())
//            return false;
//        ApiKeyAuthenticationToken other = (ApiKeyAuthenticationToken) obj;
//        if (apiKey == null) {
//            if (other.apiKey != null)
//                return false;
//        } else if (!apiKey.equals(other.apiKey))
//            return false;
//        return true;
//    }
//
//    @Override
//    public int hashCode() {
//        final int prime = 31;
//        int result = 1;
//        result = prime * result + ((apiKey == null) ? 0 : apiKey.hashCode());
//        return result;
//    }
//
//    @Override
//    public AuthenticationTokenMetaData getMetaData() {
//        return metaData;
//    }
//
//    @Override
//    public int getPreferredMatchKey() {
//        return ApiKeyAccessMatchValue.API_KEY.getNumericValue();
//    }
//
//    @Override
//    public String getPreferredMatchValue() {
//        return apiKeyHash;
//    }
//
//    @Override
//    protected String generateUniqueId() {
//        return apiKeyHash;
//    }
//
//    public String getApiKeyHash() {
//        return apiKeyHash;
//    }
//    
//    private String generateSha256Hash(String input) {
//        return KeyTools.getSha256Fingerprint(input);
//    }
//}

