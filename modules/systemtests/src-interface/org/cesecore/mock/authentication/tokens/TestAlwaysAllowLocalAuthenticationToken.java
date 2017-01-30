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
package org.cesecore.mock.authentication.tokens;

import java.security.Principal;
import java.util.HashSet;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * This token is God-token that can be sent via remote (and should never be deployed). It's purpose is to simplify boilerplate work in system tests, and
 * should not be used as a substitute for proper authentication. 
 * 
 * 
 * Example usage: TestAlwaysAllowLocalAuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal function abc"));
 * 
 * 
 * @version $Id$
 */
public class TestAlwaysAllowLocalAuthenticationToken extends AuthenticationToken {

    private static final long serialVersionUID = -3942437717641924829L;

    public TestAlwaysAllowLocalAuthenticationToken(final Principal principal) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 3125729459998373943L;

            {
                add(principal);
            }
        }, null);

    }
    
    public TestAlwaysAllowLocalAuthenticationToken(final String username) {
        this(new UsernamePrincipal(username));
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
       return true;
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
        return InternalMatchValue.DEFAULT;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {
        return InternalMatchValue.INSTANCE;
    }
    
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
        public boolean isDefaultValue() {
            return numericValue == DEFAULT.numericValue;
        }
    }

    @Override
    protected String generateUniqueId() {
        return generateUniqueId(getPrincipals().iterator().next().getName());
    }
}
