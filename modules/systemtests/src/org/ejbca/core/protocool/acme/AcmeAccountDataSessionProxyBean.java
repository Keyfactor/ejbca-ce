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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.protocol.acme.AcmeAccount;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionProxyRemote;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionRemote;

/**
 * @see AcmeAccountDataSessionRemote
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAccountDataSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeAccountDataSessionProxyBean implements AcmeAccountDataSessionProxyRemote {

    @EJB
    private AcmeAccountDataSessionLocal acmeAccountDataSession;

    @Override
    public String createOrUpdate(AcmeAccount acmeAccount) throws ApprovalException, ApprovalRequestExpiredException, WaitingForApprovalException {
        return acmeAccountDataSession.createOrUpdate(acmeAccount);
    }

    @Override
    public void remove(String accountId) {
        acmeAccountDataSession.remove(accountId);
    }

}
