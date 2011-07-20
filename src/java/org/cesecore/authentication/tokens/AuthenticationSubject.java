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
import java.util.Set;

/**
 * This class represents a Subject for the purpose of authentication/authorization. javax.security.auth.Subject was not implemented due to being
 * overly coupled with the JAAS paradigm. In order to avoid confusion with the End Entity concept, the word 'user' is avoided in both contexts.
 * 
 * TODO: Make proper hashcode/compare methods.
 * 
 * Based on cesecore version:
 *      AuthenticationSubject.java 508 2011-03-10 13:34:41Z mikek
 * 
 * @version $Id$
 * 
 */
public class AuthenticationSubject implements Serializable {

    private static final long serialVersionUID = 793575035911984396L;

    protected final Set<Principal> principals;
    protected final Set<?> credentials;
    
    public AuthenticationSubject(Set<Principal> principals, Set<?> credentials) {
        this.principals = principals;
        this.credentials = credentials;
    }

    public Set<Principal> getPrincipals() {
        return principals;
    }


    public Set<?> getCredentials() {
        return credentials;
    }

}
