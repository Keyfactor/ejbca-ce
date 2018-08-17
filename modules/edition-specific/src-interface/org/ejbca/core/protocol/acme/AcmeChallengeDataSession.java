package org.ejbca.core.protocol.acme;

import java.util.List;

/**
 * @version $Id: AcmeChallengeDataSession.java 25797 2017-05-04 15:52:00Z jeklund $
 */
public interface AcmeChallengeDataSession {

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
