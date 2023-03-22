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
import java.util.Date;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.crl.CRLInfo;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
@Local
public interface PublishingCrlSessionLocal extends PublishingCrlSession {

    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their CRLs. A CRL is created: 1. if the current CRL expires
     * within the crloverlaptime (milliseconds) 2. if a crl issue interval is defined (>0) a CRL is issued when this interval has passed, even if the
     * current CRL is still valid
     * <p>
     * This method can be called by a scheduler or a service.
     * <p>
     * For partitioned CRLs, each partition is created in a separate transaction.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked         
     * @param addtocrloverlaptime given in milliseconds and added to the CRL overlap time, if set to how often this method is run (poll time), it can 
     * be used to issue a new CRL if the current one expires within the CRL overlap time (configured in CA) and the poll time. The  used CRL overlap 
     * time will be (crloverlaptime + addtocrloverlaptime)
     *            
     * @return a set of all CAs that had CRLs created.                   
     */
     Set<Integer> createCRLs(AuthenticationToken admin, Collection<Integer> caids, long addtocrloverlaptime) throws AuthorizationDeniedException;

    /**
     * Method that checks if there are any delta CRLs needed to be updated and then creates them. This method can be called by a scheduler or a 
     * service.
     * <p>
     * For partitioned CRLs, each partition is created in a separate transaction.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked           
     * @param crloverlaptime A new delta CRL is created if the current one expires within the crloverlaptime given in milliseconds
     *            
     * @return a set of all CAs that had CRLs created.               
     */
     Set<Integer> createDeltaCRLs(AuthenticationToken admin, Collection<Integer> caids, long crloverlaptime) throws AuthorizationDeniedException;
    
    /**
     * Method that checks if the delta CRL needs to be updated and then creates
     * it.
     * <p>
     * For partitioned CRLs, each partition is created in a separate transaction.
     * 
     * @param admin administrator performing the task
     * @param caid the id of the CA this operation regards
     * @param crloverlaptime A new delta CRL is created if the current one expires within the crloverlaptime given in milliseconds
     *       
     * @return true if a Delta CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    boolean createDeltaCrlConditioned(AuthenticationToken admin, int caid, long crloverlaptime)
            throws CryptoTokenOfflineException, CAOfflineException, CADoesntExistsException, AuthorizationDeniedException;

    /** Internal method, do not use. Needs to be here for transaction management. */
    String internalCreateCRL(AuthenticationToken admin, CA ca, int crlPartitionIndex, CRLInfo lastBaseCrlInfo, final Date validFrom)
            throws CAOfflineException, CryptoTokenOfflineException, AuthorizationDeniedException;

    /**
     * Generates a new CRL by looking in the database for revoked certificates
     * and generating a CRL. This method also "archives" certificates when after
     * they are no longer needed in the CRL.
     * Generates the CRL and stores it in the database.
     * <p>
     * 
     *  Internal method, do not use. Needs to be here for transaction management. 
     *
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param lastBaseCrlInfo CRLInfo on the last base CRL created by this CA, or null, if no base CRL has been created before
     * @return fingerprint (primary key) of the generated CRL or null if
     *            generation failed
     * @throws AuthorizationDeniedException
     * @throws javax.ejb.EJBException if a communications- or system error occurs
     */
    byte[] internalCreateDeltaCRL(AuthenticationToken admin, CA ca, int crlPartitionIndex, CRLInfo lastBaseCrlInfo)
            throws CryptoTokenOfflineException, CAOfflineException, AuthorizationDeniedException;

}
