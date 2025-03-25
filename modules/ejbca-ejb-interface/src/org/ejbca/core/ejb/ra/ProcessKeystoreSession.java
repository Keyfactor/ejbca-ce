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
package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.ejbca.core.model.keyimport.KeyImportException;

/**
 * Processes one keystore during the key import process. Split from KeyImportSession for transaction management purposes.
 */
public interface ProcessKeystoreSession {

    /**
     * Processes one keystore during key import.
     *
     * @param authenticationToken authentication token
     * @param keystoreData information about one keystore entry
     * @param caInfo information about a CA
     * @param caData CA data
     * @param certificateProfileId id of the certificate profile to be used during key import
     * @param endEntityProfileId id of the end entity profile to be used during key import
     * @throws KeyImportException
     */
    void processKeyStore(AuthenticationToken authenticationToken, KeyImportKeystoreData keystoreData, CAInfo caInfo,
                                     CAData caData, int certificateProfileId, int endEntityProfileId) throws KeyImportException;
}
