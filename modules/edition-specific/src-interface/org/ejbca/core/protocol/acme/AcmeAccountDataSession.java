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
import java.util.LinkedHashMap;

/**
 * @version $Id: EstDispatcherSession.java 25797 2017-05-04 15:52:00Z jeklund $
 */
//@Local
public interface AcmeAccountDataSession {

    /**
     * Get AcmeAccount by accountId.
     *
     * @return the AcmeAccount.
     */
    LinkedHashMap<Object,Object> getAccountDataById(final String accountId);

    /**
     * Get AcmeAccount by publicKeyStorageId.
     *
     * @return the AcmeAccount.
     */
    String getAccountIdByPublicKeyStorageId(final String publicKeyStorageId);

    /**
     * Create or update the AcmeAccount.
     *
     * @return the persisted version of the AcmeAccount.
     */
    String persist(final String accountIdParam, final String currentKeyId, final LinkedHashMap<Object,Object> dataMap);
}
