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

import java.util.List;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionProxyRemote;

/**
 *
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeOrderDataSessionProxyBean implements AcmeOrderDataSessionProxyRemote {

    @EJB
    private AcmeOrderDataSessionLocal acmeOrderDataSession;

    @Override
    public String createOrUpdate(AcmeOrder acmeOrder) {
        return acmeOrderDataSession.createOrUpdate(acmeOrder);
    }

    @Override
    public List<String> createOrUpdate(List<AcmeOrder> acmeOrders) {
        return acmeOrderDataSession.createOrUpdate(acmeOrders);
    }
    
    @Override
    public void remove(String orderId) {
        acmeOrderDataSession.remove(orderId);
    }
}
