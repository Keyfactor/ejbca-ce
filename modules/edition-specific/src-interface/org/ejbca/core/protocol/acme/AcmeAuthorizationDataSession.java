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

/**
 * @version $Id$
 */
public interface AcmeAuthorizationDataSession {
    static final String ACME_MODULE = "acme";


    /**
     *
     * @param authorizationId the ID of the authorization
     * @return the sought authorization, or null if none exists
     */
    AcmeAuthorization getAcmeAuthorization(String authorizationId);

    /**
     *
     * @param orderId the ID of the order
     * @return list of sought authorizations, or null if none exists
     */
    List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId);

    /**
     *
     * @param accountId the ID of the account
     * @return list of sought authorizations, or null if none exists
     */
    List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId);
    
    /**
    *
    * @param accountId the ID of the account
    * @param identifiers the list of ACME identifiers
    * @return list of sought pre-authorizations, or null if none exists
    */
   List<AcmeAuthorization> getAcmePreAuthorizationsByAccountIdAndIdentifiers(String accountId, List<AcmeIdentifier> identifiers);

}
