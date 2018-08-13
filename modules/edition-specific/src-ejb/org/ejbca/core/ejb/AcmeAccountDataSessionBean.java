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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.acme.AcmeAccountData;
import org.ejbca.core.protocol.acme.AcmeAccount;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionRemote;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 *
 * @version $Id: AcmeAccountDataSessionBean.java 27609 2017-12-20 15:55:45Z mikekushner $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAccountDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AcmeAccountDataSessionBean implements AcmeAccountDataSessionRemote, AcmeAccountDataSessionLocal {
    
    @Override
    public String createOrUpdate(final AcmeAccount acmeAccount) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAccountData find(final String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAccount getAcmeAccount(final String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAccountData findByPublicKeyStorageId(final String publicKeyStorageId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAccount getAcmeAccountByPublicKeyStorageId(final String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void remove(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");        
    }
}
