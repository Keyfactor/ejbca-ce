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

import java.util.Set;

import javax.ejb.Local;

import org.ejbca.acme.AcmeOrderData;

/**
 * Local interface for AcmeOrderDataSession
 * 
 * @version $Id: AcmeOrderDataSessionLocal.java 29587 2018-08-07 15:25:52Z tarmor $
 *
 */

@Local
public interface AcmeOrderDataSessionLocal extends AcmeOrderDataSession {

    /**
     * @param orderId the order ID of an AcmeOrderData row
     * @return the sought object, or null if not found
     */
    AcmeOrderData find(final String orderId);
    
    /**
     * @param accountId the account ID of an AcmeOrderData row
     * @return the sought object, or null if not found
     */
    Set<AcmeOrderData> findByAccountId(final String accountId);

    /**
     * @param fingerprint the fingerprint of an AcmeOrderData row
     * @return the sought objects, or null if not found
     */
    Set<AcmeOrderData> findFinalizedAcmeOrdersByFingerprint(final String fingerprint);
}
