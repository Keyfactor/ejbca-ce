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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Set;

import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * A token returned by the act of authentication. Ownership of such a token denotes that the caller has previously authenticated herself via the
 * Authentication session bean.
 * 
 * The Sets of Principals and credentials contained within this class will correspond to the subset of those found in the Subject class submitted for
 * authentication used for that process.
 * 
 * @version $Id$
 * 
 */
public abstract class AuthenticationToken implements Serializable {

    private static final long serialVersionUID = 1888731103952962350L;

    private final Set<? extends Principal> principals;
    private final Set<?> credentials;
    private transient String uniqueId = null;

    public AuthenticationToken(Set<? extends Principal> principals, Set<?> credentials) {
        this.principals = principals;
        this.credentials = credentials;
    }

    public Set<? extends Principal> getPrincipals() {
        return principals;
    }

    public Set<?> getCredentials() {
        return credentials;
    }

    /**
     * This method will take an <code>AccessUserAspectData</code> entity and return whether or not it matches to this AuthenticationToken. Will 
     * specifically check for locality if required. 
     * 
     * @param accessUser An <code>AccessUserAspectData</code> entity to match.
     * @return <code>true</code> if matching.
     * @throws AuthenticationFailedException if any authentication errors were encountered during process
     */
    public abstract boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException;
        
    @Override
    public abstract boolean equals(Object authenticationToken);
    
    @Override
    public abstract int hashCode();

    /**
     * Default way of returning the user information of the user(s) this authentication token belongs to.
     * This should never return sensitive information, since it is used in logging (CESeCore.FAU_GEN.1.2).
     * @return a comma-separated list of all principal names in this token
     */
    @Override
    public String toString() {
    	final StringBuilder sb = new StringBuilder();
    	final Set<? extends Principal> principals = getPrincipals();
    	if (principals != null) {
    		for (final Principal principal : principals) {
    			if (sb.length() > 0) {
        			sb.append(", ");
    			}
    			sb.append(principal.getName());
    		}
    	}
    	return sb.toString();
    }
    
    /**
     * 
     * 
     * @param tokenType String a String from an AccessMatchValue derivative that matches this token type.
     * @return true if the given value matches this AuthenticationToken's inherent token type.
     */
    public abstract boolean matchTokenType(String tokenType);
    
    /**
     * 
     * @return the AccessMatchValue inherent to the implementing token type.
     */
    public abstract AccessMatchValue getDefaultMatchValue();
    
    /**
     * 
     * @param databaseValue the numeric value from the database.
     * @return the enum implementing AccessMatchValue that matches the given numeric value from the database.
     */
    public abstract AccessMatchValue getMatchValueFromDatabaseValue(Integer databaseValue);
    
    /** @return a String that is guaranteed to be unique across all AuthenticationTokens of this type. */
    protected abstract String generateUniqueId();

    /** @return a hex-encoded string of the hash over all the provided arguments */
    protected String generateUniqueId(final Object...arguments) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            for (final Object argument : arguments) {
                messageDigest.update((String.valueOf(argument)+";").getBytes(StandardCharsets.UTF_8));
            }
            return new String(Hex.encode(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
    
    /** @return a String that is guaranteed to be unique across all AuthenticationTokens. */
    public String getUniqueId() {
        if (uniqueId==null) {
            uniqueId = getTokenType() + ";" + generateUniqueId();
        }
        return uniqueId;
    }

    /** @return the type identifier of this AuthenticationToken */
    public String getTokenType() {
        return getDefaultMatchValue().getTokenType();
    }
}
