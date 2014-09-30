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
package org.ejbca.core.ejb.crl;

import java.util.Collection;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublishingCrlProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublishingCrlProxySessionBean implements PublishingCrlProxySessionRemote {

    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    
    @Override
    public int createCRLs(AuthenticationToken admin, Collection<Integer> caids, long addtocrloverlaptime) throws AuthorizationDeniedException {
        return publishingCrlSession.createCRLs(admin, caids, addtocrloverlaptime);
    }

    @Override
    public int createDeltaCRLs(AuthenticationToken admin, Collection<Integer> caids, long crloverlaptime) throws AuthorizationDeniedException {
        return publishingCrlSession.createDeltaCRLs(admin, caids, crloverlaptime);
    }

    @Override
    public boolean createDeltaCRLnewTransactionConditioned(AuthenticationToken admin, int caid, long crloverlaptime)
            throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException {
        return publishingCrlSession.createDeltaCRLnewTransactionConditioned(admin, caid, crloverlaptime);
    }

}
