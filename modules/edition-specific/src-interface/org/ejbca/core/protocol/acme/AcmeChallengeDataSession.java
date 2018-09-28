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
package org.ejbca.core.protocol.acme;

import java.util.List;

/**
 * @version $Id$
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
