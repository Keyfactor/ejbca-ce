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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionProxyRemote;

/**
 * @version $Id: AcmeOrderDataSessionProxyBean.java 29630 2018-08-14 08:55:21Z tarmor $
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeOrderDataSessionProxyRemote")
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
