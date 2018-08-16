package org.ejbca.core.protocol.acme;

import java.util.List;

/**
 * @version $Id: AcmeChallengeDataSession.java 25797 2017-05-04 15:52:00Z jeklund $
 */
public interface AcmeChallengeDataSession {

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
     *
     * @param challengeId the ID of the challenge
     * @return the sought challenge, or null if none exists
     */
    AcmeChallenge getAcmeChallenge(final String challengeId);

    /**
     *
     * @param authorizationId the ID of the authorization
     * @return the sought challenge list, or null if none exists
     */
    List<AcmeChallenge> getAcmeChallengesByAuthorizationId(final String authorizationId);
}
