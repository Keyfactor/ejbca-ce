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

import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * An authentication token that always matches the provided AccessUserAspectData if the AuthenticationToken was created in the same JVM as it is
 * verified.
 * 
 * Example usage: AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("Internal function abc");
 * 
 * @version $Id$
 */
public class AlwaysAllowLocalAuthenticationToken extends LocalJvmOnlyAuthenticationToken {

    private static final long serialVersionUID = -3942437717641924829L;

    public static final AlwaysAllowLocalAuthenticationTokenMetaData metaData = new AlwaysAllowLocalAuthenticationTokenMetaData();
    
    public AlwaysAllowLocalAuthenticationToken(final Principal principal) {
        super(new HashSet<Principal>(Arrays.asList(principal)), null);
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
        return generateUniqueId(super.isCreatedInThisJvm());
    }

    @Override
    public AlwaysAllowLocalAuthenticationTokenMetaData getMetaData() {
        return metaData;
    }
}
