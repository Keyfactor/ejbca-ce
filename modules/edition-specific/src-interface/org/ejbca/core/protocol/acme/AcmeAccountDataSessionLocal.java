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

import jakarta.ejb.Local;

import org.ejbca.acme.AcmeAccountData;

/**
 * Local interface for AcmeAccountDataSession
 * 
 * @version $Id$
 *
 */

@Local
public interface AcmeAccountDataSessionLocal extends AcmeAccountDataSession {

    /**
     * @param accountId the account ID of an AcmeAccountData row
     * @return the sought object, or null if not found
     */
    AcmeAccountData find(final String accountId);

    /**
     * 
     * @param publicKeyStorageId the public key storage ID
     * @return the sought object, or null if not found
     */
    AcmeAccountData findByPublicKeyStorageId(final String publicKeyStorageId);
    
    /**
     * Create or update the AcmeAccount.
     *
     * @return the persisted version of the AcmeAccount.
     */
    String createOrUpdate(final AcmeAccount acmeAccount);
    
    /**
     * Removes an ACME account with the given ID. Fails silently if no such ACME account exists. 
     * 
     * @param accountId the ACME account ID
     */
    void remove(final String accountId);

}
