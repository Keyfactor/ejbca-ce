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

import java.util.List;

import javax.ejb.Local;

import org.ejbca.acme.AcmeAuthorizationData;

/**
 * Local interface for AcmeAuthorizationDataSessionLocal
 *
 * @version $Id$
 */
@Local
public interface AcmeAuthorizationDataSessionLocal extends AcmeAuthorizationDataSession {


    /**
     * @param authorizationId the authorization ID of an AcmeAuthorizationData row
     * @return the sought object, or null if not found
     */
    AcmeAuthorizationData find(String authorizationId);

    /**
     *
     * @param orderId the order ID
     * @return the list of sought objects, or null if not found
     */
    List<AcmeAuthorizationData> findByOrderId(String orderId);

    /**
     *
     * @param accountId the account ID
     * @return the list of sought objects, or null if not found
     */
    List<AcmeAuthorizationData> findByAccountId(String accountId);

    /**
     * @param accountId the account ID
     * @param identifiers the list of ACME identifiers
     * 
     * @return the list of persisted AcmeAuthorization.
     */
    List<AcmeAuthorizationData> findPreAuthorizationsByAccountIdAndIdentifiers(String accountId, List<AcmeIdentifier> identifiers);

    /**
     * Create or update the AcmeAuthorization.
     *
     * @return the id of persisted version of the AcmeAuthorization.
     */
    String createOrUpdate(AcmeAuthorization acmeAuthorization);


    /**
     * Create or update the AcmeAuthorizations .
     */
    void createOrUpdateList(List<AcmeAuthorization> acmeAuthorizations);
    
    /**
     * Persists a data object. Used for testing ECA-10060 post upgrade.
     * 
     * @param the data object to persist.
     */
    void persistAcmeAuthorizationData(AcmeAuthorizationData data);

    /**
     * Removes an ACME authorization with the given ID. Fails silently if no such ACME Authorization exists.
     *
     * @param authorizationId the ACME authorization ID
     */
    void remove(String authorizationId);

}
