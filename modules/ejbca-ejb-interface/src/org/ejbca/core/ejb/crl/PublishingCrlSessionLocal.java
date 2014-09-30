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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Local
public interface PublishingCrlSessionLocal extends PublishingCrlSession {

    /**
     * Method that checks if there are any CRLs needed to be updated and then
     * creates their CRLs. A CRL is created: 1. if the current CRL expires
     * within the crloverlaptime (milliseconds) 2. if a crl issue interval is
     * defined (>0) a CRL is issued when this interval has passed, even if the
     * current CRL is still valid
     * 
     * This method can be called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in
     *            which case ALL CAs will be checked
     * @param addtocrloverlaptime
     *            given in milliseconds and added to the CRL overlap time, if
     *            set to how often this method is run (poll time), it can be
     *            used to issue a new CRL if the current one expires within the
     *            CRL overlap time (configured in CA) and the poll time. The
     *            used CRL overlap time will be (crloverlaptime +
     *            addtocrloverlaptime)
     */
    int createCRLs(AuthenticationToken admin, Collection<Integer> caids, long addtocrloverlaptime) throws AuthorizationDeniedException;

    /**
     * Method that checks if there are any delta CRLs needed to be updated and
     * then creates them. This method can be called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in
     *            which case ALL CAs will be checked
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     */
    int createDeltaCRLs(AuthenticationToken admin, Collection<Integer> caids, long crloverlaptime) throws AuthorizationDeniedException;
    
    /**
     * Method that checks if the delta CRL needs to be updated and then creates
     * it.
     * 
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     * @return true if a Delta CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    boolean createDeltaCRLnewTransactionConditioned(AuthenticationToken admin, int caid, long crloverlaptime) throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException;

}
