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
package org.ejbca.core.ejb.authentication.cli;

import java.security.Principal;
import java.util.HashSet;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.user.AccessUserAspect;

/**
 * This authentication token is returned as a result of a CLI authentication action. By design it's only allowed 
 * to be used once, then becomes invalid. 
 * 
 * @version $Id: AlwaysAllowLocalAuthenticationToken.java 12424 2011-08-31 15:10:44Z mikekushner $
 */
public class CliAuthenticationToken extends AuthenticationToken {

    private static final long serialVersionUID = -3942437717641924829L;

    private final long referenceId;
    
    public CliAuthenticationToken(final UsernamePrincipal principal, final long referenceId) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 5868667272584423392L;

            {
                add(principal);
            }
        }, null);
        this.referenceId = referenceId;

    }

    @Override
    public boolean matches(AccessUserAspect accessUser) {
        //TODO: Incomplete
        return true;
    }


    @Override
    public int hashCode() {
        final int prime = 37;
        int result = 1;
        result = prime * result + (int) (referenceId ^ (referenceId >>> 32));
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
        CliAuthenticationToken other = (CliAuthenticationToken) obj;
        if (referenceId != other.referenceId)
            return false;
        return true;
    }

}
