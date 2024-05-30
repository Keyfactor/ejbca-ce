/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocool.acme;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionProxyRemote;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeChallengeDataSessionProxyBean implements AcmeChallengeDataSessionProxyRemote {


    @EJB
    private AcmeChallengeDataSessionLocal acmeChallengeDataSession;

    @Override
    public String createOrUpdate(AcmeChallenge acmeChallenge) {
        return acmeChallengeDataSession.createOrUpdate(acmeChallenge);
    }

    @Override
    public void remove(String challengeId) {
        acmeChallengeDataSession.remove(challengeId);
    }
}
