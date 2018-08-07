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
     *
     * @return the persisted version of the AcmeAccount.
     */
    String persist(final AcmeAccount acmeAccount);
    
}
