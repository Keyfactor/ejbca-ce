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

import org.ejbca.core.protocol.acme.AcmeNonceSingletonLocal;

/**
 * Not available in Community Edition
 *
 * @version $Id$
 */
@Singleton
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
// We can't rely on transactions for calls that will do persistence over the RaMasterApi, so avoid the overhead of when methods are invoked
@TransactionManagement(TransactionManagementType.BEAN)
public class AcmeNonceSingletonBean implements AcmeNonceSingletonLocal {

    @Override
    public boolean isNonceValid(final String nonce) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String getReplayNonce() throws IllegalStateException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }


}
