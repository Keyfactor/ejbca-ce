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

import java.io.Serializable;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashSet;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;

/**
 * AuthenticationToken representing a user that has provided no means of authentication,
 * e.g. a client accessing an interface like public RA web pages.
 * 
 * @version $Id$
 */
public class PublicAccessAuthenticationToken extends NestableAuthenticationToken {

    private static class PublicAccessPrincipal implements Principal, Serializable {
        private static final long serialVersionUID = 1L;
        private final String principal;

        public PublicAccessPrincipal(final String principal) {
            this.principal = principal;
        }

        @Override
        public String getName() {
            return principal;
        }
    }
    
    private static final long serialVersionUID = 1L;
    public static final String TOKEN_TYPE = "PublicAccessAuthenticationToken";
    
    private final PublicAccessPrincipal principal;
    
    public PublicAccessAuthenticationToken(final String principal) {
        super(new HashSet<>(Arrays.asList(new Principal[] { new PublicAccessPrincipal(principal) })), new HashSet<>());
        this.principal = new PublicAccessPrincipal(principal);
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException {
        // Protect against spoofing by checking if this token was created locally
        if (!super.isCreatedInThisJvm()) {
            return false;
        }
        return true;
    }

    @Override
    public boolean matchTokenType(final String tokenType) {
        return tokenType.equals(TOKEN_TYPE);
    }

    @Override
    public AccessMatchValue getDefaultMatchValue() {
        return PublicAccessMatchValue.NONE;
    }

    @Override
    public AccessMatchValue getMatchValueFromDatabaseValue(final Integer databaseValue) {
        return AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(TOKEN_TYPE, databaseValue.intValue());
    }

    /** Returns information of the entity this authentication token belongs to. */
    @Override
    public String toString() {
        return principal.getName() + super.toString();
    }

    @Override
    public int hashCode() {
        return 4711 * 1 + ((principal.getName() == null) ? 0 : principal.getName().hashCode());
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
        PublicAccessAuthenticationToken other = (PublicAccessAuthenticationToken) obj;
        if (principal.getName() == null) {
            if (other.principal.getName() != null) {
                return false;
            }
        } else if (!principal.getName().equals(other.principal.getName())) {
            return false;
        }
        return true;
    }
}
