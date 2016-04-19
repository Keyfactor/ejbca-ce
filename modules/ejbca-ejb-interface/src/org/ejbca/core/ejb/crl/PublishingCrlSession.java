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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
public interface PublishingCrlSession {

    /**
     * Method that checks if there are any CRLs needed to be updated and then
     * creates their CRLs. No overlap is used. This method can be called by a
     * scheduler or a service.
     * 
     * @param admin administrator performing the task
     */
    int createCRLs(AuthenticationToken admin) throws AuthorizationDeniedException;

    /**
     * Method that checks if there are any delta CRLs needed to be updated and
     * then creates their delta CRLs. No overlap is used. This method can be
     * called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     */
    int createDeltaCRLs(AuthenticationToken admin) throws AuthorizationDeniedException;

    /**
     * Method that checks if the CRL is needed to be updated for the CA and
     * creates the CRL, if necessary. A CRL is created: 1. if the current CRL
     * expires within the crloverlaptime (milliseconds) 2. if a CRL issue
     * interval is defined (>0) a CRL is issued when this interval has passed,
     * even if the current CRL is still valid
     * 
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @param addtocrloverlaptime
     *            given in milliseconds and added to the CRL overlap time, if
     *            set to how often this method is run (poll time), it can be
     *            used to issue a new CRL if the current one expires within the
     *            CRL overlap time (configured in CA) and the poll time. The
     *            used CRL overlap time will be (crloverlaptime +
     *            addtocrloverlaptime)
     * @return true if a CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    boolean createCRLNewTransactionConditioned(AuthenticationToken admin, int caid, long addtocrloverlaptime) throws CryptoTokenOfflineException,
            CAOfflineException, CADoesntExistsException, AuthorizationDeniedException;

    /** Method that forces generation of a CRL for a certain CA
     * 
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @return true if a CRL was generated
     */
    boolean forceCRL(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException,
            CAOfflineException;

    /** Method that forces generation of a Delta CRL for a certain CA
     * 
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @return true if a CRL was generated
     */
    boolean forceDeltaCRL(AuthenticationToken admin, int caid) throws CADoesntExistsException, AuthorizationDeniedException,
            CryptoTokenOfflineException, CAOfflineException;
}
