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
package org.ejbca.core.ejb.keyrecovery;

import java.security.KeyPair;
import java.security.cert.Certificate;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Local interface for KeyRecoverySession.
 */
@Local
public interface KeyRecoverySessionLocal extends KeyRecoverySession {

    /**
     * Adds a certificates keyrecovery data to the database. This method allows a crypto token to be specified,
     * and does not require the CA to be present on the system.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keypair.
     * @param username of the administrator
     * @param keypair the actual keypair to save.
     * @param cryptoTokenId ID of crypto token to use to encrypt key.
     * @param keyAlias key alias in crypto token to use to encrypt key.
     *
     * @return false if the certificates keyrecovery data already exists, or if the crypto token was offline.
     * @throws AuthorizationDeniedException if not authorized to administer keys.
     */
    boolean addKeyRecoveryData(AuthenticationToken admin, Certificate certificate, String username, KeyPair keypair, int cryptoTokenId,
            String keyAlias) throws AuthorizationDeniedException;
 
}
