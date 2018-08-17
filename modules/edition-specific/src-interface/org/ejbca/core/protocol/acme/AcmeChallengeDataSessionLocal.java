package org.ejbca.core.protocol.acme;

import java.util.List;

import javax.ejb.Local;

import org.ejbca.acme.AcmeChallengeData;

/**
 * @version $Id: AcmeChallengeDataSessionLocal.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Local
public interface AcmeChallengeDataSessionLocal extends AcmeChallengeDataSession{

    /**
     * Create or update the AcmeChallenge.
     *
     * @return the persisted version of the AcmeChallenge.
     */
    String createOrUpdate(final AcmeChallenge acmeChallenge);

    /**
     * Create or update the AcmeChallenges.
     *
     */
    void createOrUpdateList(final List<AcmeChallenge> acmeChallenges);

    /**
     * @param challengeId the challenge ID of an AcmeChallengeData row
     * @return the sought object, or null if not found
     */
    AcmeChallengeData find(final String challengeId);

    /**
     *
     * @param authorizationId the authorization ID of an AcmeAuthorizationData
     * @return the list of objects, or empty list if none found
     */
    List<AcmeChallengeData> findByAuthorizationId(final String authorizationId);

    /**
     * Removes an ACME challenge with the given ID. Fails silently if no such ACME Challenge exists.
     *
     * @param challengeId the ACME Challenge ID
     */
    void remove(final String challengeId);
}
