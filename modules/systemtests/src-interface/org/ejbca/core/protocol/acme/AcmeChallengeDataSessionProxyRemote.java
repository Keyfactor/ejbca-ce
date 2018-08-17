package org.ejbca.core.protocol.acme;

import javax.ejb.Remote;

/**
 * Test proxy for AcmeChallengeDataSession
 * 
 * @version $Id: AcmeChallengeDataSessionProxyRemote.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Remote
public interface AcmeChallengeDataSessionProxyRemote {
    /**
     * Create or update the AcmeChallenge.
     *
     * @return the persisted version of the AcmeChallenge.
     */
    String createOrUpdate(final AcmeChallenge acmeChallenge);

    /**
     * Removes an ACME challenge with the given ID. Fails silently if no such ACME challenge exists.
     *
     * @param challengeId the ACME challenge ID
     */
    void remove(final String challengeId);
}
