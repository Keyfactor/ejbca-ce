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
     * @param accountId the account ID of an AcmeAccountData row
     * @return the sought object, or null if not found
     */
    AcmeOrderData find(final String orderId);
    
}
