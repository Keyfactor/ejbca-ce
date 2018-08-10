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

/**
 * @version $Id: AcmeAccountDataSession.java 25797 2017-05-04 15:52:00Z jeklund $
 */
public interface AcmeAccountDataSession {

    static final String ACME_MODULE = "acme";

    
    /**
     *  
     * @param accountId the ID of the account
     * @return the sought account, or null if none exists
     */
    AcmeAccount getAcmeAccount(final String accountId);
    
    /**
     *  
     * @param publicKeyStorageId the ID of the account
     * @return the sought account, or null if none exists
     */
    AcmeAccount getAcmeAccountByPublicKeyStorageId(final String publicKeyStorageId);
    
    /**
     * Create or update the AcmeAccount.
     * TODO: This should me moved into Local, but test proxies must be created first.
     *
     * @return the persisted version of the AcmeAccount.
     */
    String createOrUpdate(final AcmeAccount acmeAccount);
    
    /**
     * Removes an ACME account with the given ID. Fails silently if no such ACME account exists. 
     * TODO: This should me moved into Local, but test proxies must be created first.
     * 
     * @param accountId the ACME account ID
     */
    void remove(final String accountId);
    
}
