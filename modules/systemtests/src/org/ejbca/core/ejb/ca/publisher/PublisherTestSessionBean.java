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
package org.ejbca.core.ejb.ca.publisher;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.ejbca.mock.publisher.MockedThrowAwayRevocationPublisher;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherTestSessionBean implements PublisherTestSessionRemote {

    @Override
    public int getLastMockedThrowAwayRevocationReason() {
        return MockedThrowAwayRevocationPublisher.getLastTestRevocationReason();
    }

    @Override
    public void setLastMockedThrowAwayRevocationReason(int revocationReason) {
        MockedThrowAwayRevocationPublisher.setLastTestRevocationReason(revocationReason);
    }

}
