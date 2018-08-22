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
package org.ejbca.core.ejb;

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.acme.AcmeChallengeData;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionRemote;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 *
 * @version $Id: AcmeChallengeDataSessionBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeChallengeDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AcmeChallengeDataSessionBean implements AcmeChallengeDataSessionLocal, AcmeChallengeDataSessionRemote {
    @Override
    public String createOrUpdate(AcmeChallenge acmeChallenge) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void createOrUpdateList(List<AcmeChallenge> acmeChallenges) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeChallenge getAcmeChallenge(String challengeId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeChallenge> getAcmeChallengesByAuthorizationId(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeChallengeData find(String challengeId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeChallengeData> findByAuthorizationId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void remove(String challengeId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
