/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.crl;

import java.util.Collection;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Local interface for CrlCreateSession
 * 
 * @version $Id$
 *
 */
@Local
public interface CrlCreateSessionLocal extends CrlCreateSession {

    /**
     * Method that checks if there are any CRLs needed to be updated and then
     * creates their CRLs. A CRL is created: 1. if the current CRL expires
     * within the crloverlaptime (milliseconds) 2. if a crl issue interval is
     * defined (>0) a CRL is issued when this interval has passed, even if the
     * current CRL is still valid. This method reuses an existing CA session.
     * 
     * This method can be called by a scheduler or a service.
     * 
     * @param caSession CA session to be used, to achive atom transactions
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
     * @return the number of CRLs created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createCRLs(CaSessionLocal caSession, AuthenticationToken admin, Collection<Integer> caids, long addtocrloverlaptime) throws AuthorizationDeniedException;
    
 
    /**
     * Method that checks if there are any delta CRLs needed to be updated and
     * then creates them. This method can be called by a scheduler or a service.
     * This method reuses an existing CA session.
     * 
     * @param caSession CA session to be used, to achive atomic transations.
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in
     *            which case ALL CAs will be checked
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     * @return the number of delta CRLs created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createDeltaCRLs(CaSessionLocal caSession, AuthenticationToken admin, Collection<Integer> caids, long crloverlaptime) throws AuthorizationDeniedException;
    
    /**
     * Method that checks if the CRL is needed to be updated for the CA and
     * creates the CRL, if necessary. A CRL is created: 1. if the current CRL
     * expires within the crloverlaptime (milliseconds) 2. if a CRL issue
     * interval is defined (>0) a CRL is issued when this interval has passed,
     * even if the current CRL is still valid.
     * This method re-uses an existing CA session
     * 
     * @param caSession CA session to be used.
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
    public boolean createCRLNewTransactionConditioned(CaSessionLocal caSession, AuthenticationToken admin, int caid, long addtocrloverlaptime) throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException;
    
    /**
     * Method that checks if the delta CRL needs to be updated and then creates
     * it.
     * This method re-uses an existing CA session
     * 
     * @param caSession CA session to use
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     * @return true if a Delta CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public boolean createDeltaCRLnewTransactionConditioned(CaSessionLocal caSession, AuthenticationToken admin, int caid, long crloverlaptime) throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException;

}
