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

import org.ejbca.core.protocol.acme.AcmeNonceDataSessionLocal;

/**
 * Not available in Community Edition
 *
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeNonceDataSessionBean implements AcmeNonceDataSessionLocal {

    @Override
    public boolean useNonce(final String nonce, final long timeCreated, final long timeExpires) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void cleanUpExpired() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
