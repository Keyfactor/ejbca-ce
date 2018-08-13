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
package org.ejbca.core.protocol.acme;

import javax.ejb.EJBTransactionRolledbackException;

/**
 * Database implementation of ACME replay nonce storage.
 *
 * @version $Id: AcmeNonceDataSessionBean.java 29072 2018-05-30 09:42:10Z bastianf $
 */
public interface AcmeNonceDataSessionLocal {

    /**
     * Save a nonce to persistent storage. This will mark the nonce as "used" on all nodes
     * in the cluster.
     * @param nonce the replay nonce to store
     * @param timeCreated the time when the replay nonce was created
     * @param timeExpires the time when the replay nonce expires
     * @return true if the given nonce has NOT been used before and has not expired, false if it has expired
     * @throws EJBTransactionRolledbackException if the nonce is already present in the database
     */
    boolean useNonce(String nonce, long timeCreated, long timeExpires);

    /**
     * Remove expired nonces from the database. Nonces that expired less than an hour ago are
     * kept to account for clock drift.
     */
    void cleanUpExpired();

}