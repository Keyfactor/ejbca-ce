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

/**
 *  Test proxy for AcmeAccountDataSession
 *
 * @version $Id: AcmeAuthorizationDataSessionProxyRemote.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Remote
public interface AcmeAuthorizationDataSessionProxyRemote {
    /**
     * Create or update the AcmeAuthorization.
     *
     * @return the persisted version of the AcmeAuthorization.
     */
    String createOrUpdate(final AcmeAuthorization acmeAuthorization);

    /**
     * Removes an ACME authorization with the given ID. Fails silently if no such ACME authorization exists.
     *
     * @param authorizationId the ACME authorization ID
     */
    void remove(final String authorizationId);

}
