/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * An authentication token that always matches the provided AccessUserAspectData if the AuthenticationToken was created in the same JVM as it is
 * verified.
 * 
 * Example usage: AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("Internal function abc");
 *
 */
public class AlwaysAllowLocalAuthenticationToken extends NestableAuthenticationToken {

    private static final long serialVersionUID = -3942437717641924829L;

    public static final AlwaysAllowLocalAuthenticationTokenMetaData metaData = new AlwaysAllowLocalAuthenticationTokenMetaData();
    
    public AlwaysAllowLocalAuthenticationToken(final Principal principal) {
        // This can be written nicer like:
        // super(new HashSet<Principal>(Arrays.asList(principal)), null);
        // but we need to keep this form for backwards compatibility reasons to de-serialize ApprovalRequests. See ECA-6442
        // This form create an anonymous internal class, AlwaysAllowLocalAuthenticationToken$1.class
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 3125729459998373943L;
            {
                add(principal);
            }
        }, null);
    }

    public AlwaysAllowLocalAuthenticationToken(final String username) {
        super(new HashSet<Principal>(Arrays.asList(new UsernamePrincipal(username))), null);
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
       return super.isCreatedInThisJvm();  
    }
    
    @Override
    public int getPreferredMatchKey() {
        return AuthenticationToken.NO_PREFERRED_MATCH_KEY; // not applicable to this type of authentication token
    }
    
    @Override
    public String getPreferredMatchValue() {
        return null;
    }
    
    @Override
    public boolean equals(Object authenticationToken) {
        if (this == authenticationToken) {
            return true;
        }
        if (authenticationToken == null) {
            return false;
        }
        if (getClass() != authenticationToken.getClass()) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public int hashCode() {
        return getMetaData().getTokenType().hashCode();
    }

    @Override
    public boolean matchTokenType(String tokenType) {  
        return true;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {
        // Special legacy handling for unclear reasons..?
        return getMetaData().getAccessMatchValues().get(0);
    }
    
    @Override
    protected String generateUniqueId() {
        return generateUniqueId(super.isCreatedInThisJvm()) + ";" + super.generateUniqueId();
    }

    @Override
    public AlwaysAllowLocalAuthenticationTokenMetaData getMetaData() {
        return metaData;
    }
    
    /** Do not use since EJBCA 6.8. Kept for backwards compatibility reasons to de-serialize ApprovalRequests. See ECA-6442 */
    @SuppressWarnings("unused")
    @Deprecated 
    private static enum InternalMatchValue implements AccessMatchValue {
        INSTANCE(0), DEFAULT(Integer.MAX_VALUE);

        private static final String TOKEN_TYPE = "AlwaysAllowAuthenticationToken";
        
        private final int numericValue;
        
        private InternalMatchValue(final int numericValue) {
            this.numericValue = numericValue;
        }
        
        @Override
        public int getNumericValue() {         
            return numericValue;
        }

        @Override
        public String getTokenType() {           
            return TOKEN_TYPE;
        }

        @Override
        public boolean isIssuedByCa() {
            return false;
        }

        @Override
        public boolean isIssuedByOauthProvider() {
            return false;
        }

        @Override
        public boolean isDefaultValue() {
            return numericValue == DEFAULT.numericValue;
        }

        @Override
        public List<AccessMatchType> getAvailableAccessMatchTypes() {
            return null;
        }

        @Override
        public String normalizeMatchValue(String value) {
            return null;
        }
    }

}
