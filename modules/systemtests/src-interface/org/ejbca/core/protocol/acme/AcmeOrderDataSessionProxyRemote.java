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
 * Test proxy for AcmeAccountDataSession
 * 
 * @version $Id: AcmeAccountDataSessionProxyRemote.java 29630 2018-08-14 08:55:21Z mikekushner $
 *
 */
@Remote
public interface AcmeOrderDataSessionProxyRemote {
    /**
     * Create or update the AcmeOrder.
     *
     * @return the persisted version of the AcmeOrder.
     */
    String createOrUpdate(final AcmeOrder acmeOrder);
    
    /**
     * Removes an ACME order with the given ID. Fails silently if no such ACME order exists. 
     * 
     * @param orderId the ACME order ID
     */
    void remove(final String orderId);
}
