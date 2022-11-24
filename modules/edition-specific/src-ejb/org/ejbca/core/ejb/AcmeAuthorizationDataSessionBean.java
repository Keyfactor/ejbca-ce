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
import org.ejbca.acme.AcmeAuthorizationData;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionRemote;
import org.ejbca.core.protocol.acme.AcmeIdentifier;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAuthorizationDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AcmeAuthorizationDataSessionBean implements AcmeAuthorizationDataSessionRemote, AcmeAuthorizationDataSessionLocal {

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAuthorization getAcmeAuthorization(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorization> getAcmePreAuthorizationsByAccountIdAndIdentifiers(String accountId, List<AcmeIdentifier> identifiers) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAuthorizationData find(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AcmeAuthorizationData> findByOrderId(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorizationData> findByAccountId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorizationData> findPreAuthorizationsByAccountIdAndIdentifiers(String accountId, List<AcmeIdentifier> identifiers) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String createOrUpdate(AcmeAuthorization acmeAuthorization) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void createOrUpdateList(List<AcmeAuthorization> acmeAuthorizations) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public void persistAcmeAuthorizationData(AcmeAuthorizationData data) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void remove(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
