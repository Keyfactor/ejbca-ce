/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import javax.ejb.Remote;

import org.ejbca.acme.AcmeAuthorizationData;

/**
 *  Test proxy for AcmeAccountDataSession
 */
@Remote
public interface AcmeAuthorizationDataSessionProxyRemote {
    /**
     * Create or update the AcmeAuthorization.
     *
     * @return the persisted version of the AcmeAuthorization.
     */
    String createOrUpdate(AcmeAuthorization acmeAuthorization);

    /**
     * Removes an ACME authorization with the given ID. Fails silently if no such ACME authorization exists.
     *
     * @param authorizationId the ACME authorization ID
     */
    void remove(String authorizationId);
    
    /**
     * Persists a data object. Used for testing ECA-10060 post upgrade.
     * 
     * @param the data object to persist.
     */
    void persistAcmeAuthorizationData(AcmeAuthorizationData data);
    
    /**
     * Fetches the data object. Used for testing ECA-10060 post upgrade.
     * 
     * @param authorizationId the ACME authorization ID
     */
    AcmeAuthorizationData find(String authorizationId);

}
