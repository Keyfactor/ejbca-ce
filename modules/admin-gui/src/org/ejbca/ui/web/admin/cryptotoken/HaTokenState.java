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
public class HaTokenState implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(HaTokenState.class);

    private HashMap<Integer, Long> lastKnownSessionState = new HashMap<>();
    private static HashMap<Integer, Long> lastKnownJvmState = new HashMap<>();

    /**
     * Find all tokens that changed on another node for this session and update them.
     * This should be a noop on non HA deployments.
     */
    public void refreshOutOfDateTokens(CryptoTokenSessionLocal cryptoTokenSession) {
        var tokensToUpdate = new HashSet<Integer>();
        synchronized (this) {
            for (var tokenId : lastKnownSessionState.keySet()) {
                var sessionStateMarker = lastKnownSessionState.get(tokenId);
                if (lastKnownJvmState.get(tokenId) == sessionStateMarker) {
                    continue;
                }
                
                log.info("Token " + tokenId + " different in this session and this JVM.  Need to update.");
                tokensToUpdate.add(tokenId);
            }
        }

        for (Integer tokenId : tokensToUpdate) {
            cryptoTokenSession.flushId(tokenId);
            synchronized (this) {
                log.info("Updating token " + tokenId + " due to change in current session");
                lastKnownJvmState.put(tokenId, lastKnownSessionState.get(tokenId));
            }
        }
    }

    public void tokenChanged(int tokenId) {
        var random = new Random();
        var marker = random.nextLong();
        synchronized (this) {
            lastKnownJvmState.put(tokenId, marker);
        }
        lastKnownSessionState.put(tokenId, marker);
    }

}
