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
package org.ejbca.ui.web.admin.cryptotoken;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.CryptoTokenSessionLocal;

/**
 * I keep track of crypto tokens that have changed during the current session 
 * and can compare those with the last known state on the current JVM.  If they're different
 * (which can happen in HA mode when we the user is directed to a different JVM instance)
 * I can update the tokens to reflect that change.
 */
public class CurrentSessionCryptoTokenChanges implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CurrentSessionCryptoTokenChanges.class);

    /**
     * I hold a random token from the last time the token was updated for the users session
     */
    private HashMap<Integer, Long> lastKnownSessionState = new HashMap<>();

    /**
     * I hold a random token from the last time the token was updated on this JVM
     */
    private static HashMap<Integer, Long> lastKnownJvmState = new HashMap<>();

    /**
     * Find all tokens that changed on another node for this session and update them.
     * This should essentially be a noop on non-HA deployments.
     * 
     * @return true if any tokens were updated
     */
    public boolean refreshChangedCryptoTokens(CryptoTokenSessionLocal cryptoTokenSession) {
        var tokensToUpdate = new HashSet<Integer>();
        synchronized (this) {
            for (var tokenId : lastKnownSessionState.keySet()) {
                var sessionStateMarker = lastKnownSessionState.get(tokenId);

                // if lastKnownJvmState doesn't contain tokenId, it will be null and not equal
                if (sessionStateMarker.equals(lastKnownJvmState.get(tokenId))) {
                    continue;
                }

                log.debug("Token " + tokenId + " different in this session and this JVM.  Need to update.");
                tokensToUpdate.add(tokenId);
            }
        }

        for (Integer tokenId : tokensToUpdate) {
            cryptoTokenSession.flushId(tokenId);
            synchronized (this) {
                log.debug("Updating token " + tokenId + " due to change in current session");
                lastKnownJvmState.put(tokenId, lastKnownSessionState.get(tokenId));
            }
        }

        return !tokensToUpdate.isEmpty();
    }

    /**
     * Remember that this token has changed in the current session and on this JVM
     */
    public void tokenChanged(int tokenId) {
        log.debug("Token " + tokenId + " changed");
        var random = new Random();
        var marker = random.nextLong();
        synchronized (this) {
            lastKnownJvmState.put(tokenId, marker);
        }
        lastKnownSessionState.put(tokenId, marker);
    }

    void changeOneJvmState() {
        int tokenId = lastKnownJvmState.keySet().iterator().next();
        lastKnownJvmState.put(tokenId, lastKnownJvmState.get(tokenId) + 1);
    }
}
