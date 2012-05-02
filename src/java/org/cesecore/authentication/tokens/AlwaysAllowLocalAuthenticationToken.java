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
import java.util.HashSet;

import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * An authentication token that always matches the provided AccessUserAspectData if the AuthenticationToken was created in the same JVM as it is
 * verified.
 * 
 * Example usage: AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal function abc"));
 * 
 * Based on cesecore version: AlwaysAllowLocalAuthenticationToken.java 948 2011-07-18 09:04:26Z mikek
 * 
 * @version $Id$
 */
public class AlwaysAllowLocalAuthenticationToken extends LocalJvmOnlyAuthenticationToken {

    private static final long serialVersionUID = -3942437717641924829L;

    public AlwaysAllowLocalAuthenticationToken(final Principal principal) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 3125729459998373943L;

            {
                add(principal);
            }
        }, null);

    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
       return super.isCreatedInThisJvm();  
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
        return "AlwaysAllowLocalAuthenticationToken".hashCode();
    }

    @Override
    public boolean matchTokenType(String tokenType) {  
        return true;
    }

    @Override
    public AccessMatchValue getDefaultMatchValue() {
        return DefaultInternalMatchValue.INSTANCE;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {
        return InternalMatchValue.INSTANCE;
    }
    
    private static enum InternalMatchValue implements AccessMatchValue {
        INSTANCE;

        private static final String TOKEN_TYPE = "AlwaysAllowAuthenticationToken";
        
        @Override
        public int getNumericValue() {         
            return 0;
        }

        @Override
        public String getTokenType() {           
            return TOKEN_TYPE;
        }
        
    }
    
    private static enum DefaultInternalMatchValue implements AccessMatchValue {
        INSTANCE;

        private static final String TOKEN_TYPE = "AlwaysAllowAuthenticationToken";
        
        @Override
        public int getNumericValue() {         
            return Integer.MAX_VALUE;
        }

        @Override
        public String getTokenType() {           
            return TOKEN_TYPE;
        }
        
    }
}
