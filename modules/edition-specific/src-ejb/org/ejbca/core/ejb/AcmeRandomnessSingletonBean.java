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

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

import org.ejbca.core.protocol.acme.AcmeRandomnessSingletonLocal;

/**
 * Source of required randomness used in the ACME protocol.
 * 
 * @version $Id$
 */
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.CONTAINER)
// We can't rely on transactions for calls that will do persistence over the RaMasterApi, so avoid the overhead of when methods are invoked
@TransactionManagement(TransactionManagementType.BEAN)
public class AcmeRandomnessSingletonBean implements AcmeRandomnessSingletonLocal {
    
    @Override
    public String generateAcmeChallengeToken() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String generateAcmeOrderEnrollmentCode() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public byte[] generateAcmeNodeId(final int byteCount) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String generateAcmeAccountId() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String generateAcmeOrderId() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String generateAcmeChallengeId()  {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public byte[] generateReplayNonceSharedSecret(final int byteCount) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
