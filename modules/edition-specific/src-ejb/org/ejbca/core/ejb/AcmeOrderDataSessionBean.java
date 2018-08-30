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
import java.util.Set;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.acme.AcmeOrderData;
import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionRemote;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 *
 * @version $Id: AcmeOrderDataSessionBean.java 27609 2017-12-20 15:55:45Z tarmor $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeOrderDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AcmeOrderDataSessionBean implements AcmeOrderDataSessionRemote, AcmeOrderDataSessionLocal {
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeOrderData find(final String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeOrder getAcmeOrder(final String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
        
    }

    @Override
    public Set<AcmeOrder> getAcmeOrdersByAccountId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(String fingerprint) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public Set<AcmeOrderData> findByAccountId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public Set<AcmeOrderData> findFinalizedAcmeOrdersByFingerprint(final String fingerprint) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public String createOrUpdate(final AcmeOrder acmeOrder) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<String> createOrUpdate(final List<AcmeOrder> acmeOrders) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public void remove(final String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public void removeAll(final List<String> orderIds) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
