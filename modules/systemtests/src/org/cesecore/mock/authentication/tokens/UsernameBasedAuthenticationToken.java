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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;

/**
 * This mock of an authentication token is to provide a simple token to test authentication/authorization based
 * on a username. It shouldn't be used outside that context, and shouldn't be used to avoid proper authorization tests.
 * 
 * @version $Id$
 *
 */
public class UsernameBasedAuthenticationToken extends AuthenticationToken{
    
    public static final String TOKEN_TYPE = "UsernameBasedAuthenticationToken";
    
    private static final long serialVersionUID = -8284027258387832870L;

    private String username;
    
    public UsernameBasedAuthenticationToken(final UsernamePrincipal principal) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = -5658805274530978504L;
            {
                add(principal);
            }
        }, null);
        this.username = principal.getName();
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
        return username.equals(accessUser.getMatchValue());
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((username == null) ? 0 : username.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        UsernameBasedAuthenticationToken other = (UsernameBasedAuthenticationToken) obj;
        if (username == null) {
            if (other.username != null)
                return false;
        } else if (!username.equals(other.username))
            return false;
        return true;
    }

    @Override
    public boolean matchTokenType(String tokenType) {        
        return TOKEN_TYPE.equals(tokenType);
    }

    @Override
    public AccessMatchValue getDefaultMatchValue() {
        return UsernameAccessMatchValue.USERNAME;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue) {
        if (databaseValue != UsernameAccessMatchValue.USERNAME.getNumericValue()) {
            return null;
        } else {
            return UsernameAccessMatchValue.USERNAME;
        }
    }

}

enum UsernameAccessMatchValue implements AccessMatchValue {
    USERNAME(0);

    private static final Logger log = Logger.getLogger(UsernameAccessMatchValue.class);
    
    private int numericValue;
    private static Map<Integer, UsernameAccessMatchValue> databaseLookup;

    static {
        /*
         * This match value is registered with the token reverse lookup registry, which will allow it to be looked up from the string
         * return by the getTokenType method implemented from AccessMatchValue.  
         */  
        try {
            AccessMatchValueReverseLookupRegistry.INSTANCE.registerLookupMethod(UsernameBasedAuthenticationToken.TOKEN_TYPE,
                    UsernameAccessMatchValue.class.getMethod("matchFromDatabase", Integer.class));
        } catch (SecurityException e) {
            log.error("Failure when registering method", e);
        } catch (NoSuchMethodException e) {
            log.error("Failure when registering method", e);
        }

        /**
         * Create an internal mapping to translate from the database representation of this match value (an int)
         * to an actual match value.
         */
        databaseLookup = new HashMap<Integer, UsernameAccessMatchValue>();
        for (UsernameAccessMatchValue value : UsernameAccessMatchValue.values()) {
            databaseLookup.put(value.numericValue, value);
        }
    }

    private UsernameAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    @Override
    public int getNumericValue() {
        return numericValue;
    }

    @Override
    public String getTokenType() {
        return UsernameBasedAuthenticationToken.TOKEN_TYPE;
    }

    public static UsernameAccessMatchValue matchFromDatabase(Integer numericValue) {
        return databaseLookup.get(numericValue);
    }

}

