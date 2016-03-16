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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A NestableAuthenticationToken represents an AuthenticationToken where the original credentials has
 * passed through multiple step of authentication.
 * 
 * @version $Id$
 */
public abstract class NestableAuthenticationToken extends LocalJvmOnlyAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private static final int MAX_NESTING = 10;
    
    private NestableAuthenticationToken nestedAuthenticationToken = null;

    protected NestableAuthenticationToken(final Set<? extends Principal> principals, final Set<?> credentials) {
        super(principals, credentials);
    }

    /** @return a List of all nested AuthenticationTokens (excluding the object itself) or an empty List, never null.*/
    public List<NestableAuthenticationToken> getNestedAuthenticationTokens() {
        final List<NestableAuthenticationToken> nestedAuthenticationTokens = new ArrayList<>();
        NestableAuthenticationToken current = this.nestedAuthenticationToken;
        while (current!=null) {
            nestedAuthenticationTokens.add(current);
            // Perform a small sanity check to protect against loops or massive nesting in order to exhaust server mem 
            if (nestedAuthenticationTokens.size()>MAX_NESTING) {
                throw new IllegalStateException("Hard coded limit of number of nested AuthenticationTokens reached.");
            }
            current = current.nestedAuthenticationToken;
        }
        return nestedAuthenticationTokens;
    }

    public void appendNestedAuthenticationToken(final NestableAuthenticationToken nestedAuthenticationToken) {
        NestableAuthenticationToken current = this;
        int count = 0;
        while (true) {
            // If the nested token we are appending was created locally, we consider all to be created locally as well
            if (nestedAuthenticationToken.isCreatedInThisJvm() && !current.isCreatedInThisJvm()) {
                current.initRandomToken();
            }
            if (current.nestedAuthenticationToken==null) {
                current.nestedAuthenticationToken = nestedAuthenticationToken;
                break;
            }
            // Perform a small sanity check to protect against loops or massive nesting in order to exhaust server mem 
            if (count++>MAX_NESTING) {
                throw new IllegalStateException("Hard coded limit of number of nested AuthenticationTokens reached.");
            }
            current = current.nestedAuthenticationToken;
        }
    }

    /** Returns information of the entity this authentication token belongs to. */
    @Override
    public String toString() {
        if (nestedAuthenticationToken!=null) {
            return " [via] " + nestedAuthenticationToken.toString();
        }
        return "";
    }
}
