/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;

/**
 * Due to being sent over remote, this token needs to protect against two threats: replay and interception.
 * 
 * Replay is stopped via the CliAuthenticationTokenReferenceRegistry, where each authentication token must register prior to its first authorization.
 * Once authorized the token is removed from that registry, and further attempts to authorize the same token will fail. In order to allow the same
 * token to be used several times within the local environment, the transient 'isVerified'-flag is set upon the first authorization.
 * 
 * Interception of this token being transmitted risks making the password hash known, which can be used to forge future tokens. To guard against this
 * threat, the password hash is never transmitted in cleartext. Instead a SHA1 hash is calculated on server side, registered here but not transmitted
 * back (see CliAuthenticationToken's clone method). Meanwhile, on the client side the SHA1 hash is recalculated and stored in the token, and at
 * authorization the two are compared to make sure that the token is valid. Note that this implies that true athentication (password comparison) is
 * not performed until the first authorization act.
 * 
 * 
 * @version $Id$
 * 
 */
public enum CliAuthenticationTokenReferenceRegistry {
    INSTANCE;

    private static final Logger log = Logger.getLogger(CliAuthenticationTokenReferenceRegistry.class);

    private Map<Long, CliAuthenticationToken> tokenRegistry;

    private CliAuthenticationTokenReferenceRegistry() {
        tokenRegistry = Collections.synchronizedMap(new HashMap<Long, CliAuthenticationToken>());
    }

    /**
     * Verifies that the sha1Hash supplied as a parameter matches the one in the token registered by the given reference number.
     * 
     * @param referenceNumber a reference number to a registered token.
     * @param sha1Hash the hash to check against.
     * @return true if the hash matches.
     * @throws AuthenticationFailedException if an attempt is made to verify password on an non-existent or already used token
     */
    public boolean verifySha1Hash(Long referenceNumber, String sha1Hash) throws AuthenticationFailedException {
        if (tokenRegistry.containsKey(referenceNumber)) {
            return sha1Hash.equals(tokenRegistry.get(referenceNumber).getSha1Hash());
        } else {
            throw new AuthenticationFailedException("Attempt was made to verify password on an non-existent or already used token.");
        }
    }

    /**
     * Register an authentication token to this registry.
     * 
     * @return the reference number to that token.
     */
    public void registerToken(final CliAuthenticationToken token) {
        CliAuthenticationToken safetyCopy = token.clone();
        safetyCopy.setSha1Hash(token.getSha1Hash());
        tokenRegistry.put(token.getReferenceNumber(), safetyCopy);
        if (log.isTraceEnabled()) {
            log.trace("Registered new CliAuthenticationToken: "+safetyCopy+", with reference number: "+safetyCopy.getReferenceNumber());
        }
    }

    /**
     * Unregisters a token from the registry. Note that this method is safe from querying, since it's only available from inside the same process.
     * 
     * @param referenceNumber a reference number to a CLI authentication token.
     * 
     * @return true if token was successfully removed, false otherwise
     */
    public boolean unregisterToken(Long referenceNumber) {
        if (tokenRegistry.containsKey(referenceNumber)) {
            tokenRegistry.remove(referenceNumber);
            if (log.isTraceEnabled()) {
                log.trace("Unregistered CliAuthenticationToken with reference number: "+referenceNumber);
            }
            return true;
        } else {
            return false;
        }
    }

}
