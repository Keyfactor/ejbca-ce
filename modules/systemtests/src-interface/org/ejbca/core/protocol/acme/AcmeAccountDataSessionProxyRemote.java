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

import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * Test proxy for AcmeAccountDataSession.
 */
@Remote
public interface AcmeAccountDataSessionProxyRemote {
    
    /**
     * Create or update the AcmeAccount.
     *
     * @return the persisted version of the AcmeAccount.
     */
    String createOrUpdate(final AcmeAccount acmeAccount) throws ApprovalException, ApprovalRequestExpiredException, WaitingForApprovalException;
    
    /**
     * Removes an ACME account with the given ID. Fails silently if no such ACME account exists. 
     * 
     * @param accountId the ACME account ID
     */
    void remove(final String accountId);
}
