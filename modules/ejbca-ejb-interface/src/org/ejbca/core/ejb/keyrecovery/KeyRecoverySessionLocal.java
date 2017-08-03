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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.keys.util.KeyPairWrapper;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;

/**
 * Local interface for KeyRecoverySession.
 */
@Local
public interface KeyRecoverySessionLocal extends KeyRecoverySession {

    /**
     * Adds a certificates keyrecovery data to the database. This method allows a crypto token to be specified,
     * and does not require the CA to be present on the system.
     * 
     * <p>Additionally, this method expects the caller to do the authorization checks, using the authorization
     * HashMaps available on the RA.
     *
     * @param admin the administrator calling the function (used for audit logging)
     * @param certificate the certificate used with the keypair.
     * @param username of the administrator
     * @param keypair the actual keypair to save.
     * @param cryptoTokenId ID of crypto token to use to encrypt key.
     * @param keyAlias key alias in crypto token to use to encrypt key.
     *
     * @return false if the certificates keyrecovery data already exists, or if the crypto token was offline.
     * @see KeyRecoverySession#addKeyRecoveryData
     */
    boolean addKeyRecoveryDataInternal(AuthenticationToken admin, CertificateWrapper certificate, String username, KeyPairWrapper keypair, int cryptoTokenId,
            String keyAlias);

    /**
     * Returns the keyrecovery data for a user. Observe only one certificates
     * key can be recovered for every user at the time.
     * 
     * <p>This method expects the caller to do the authorization checks, using the authorization
     * HashMaps available on the RA.
     * 
     * <p><b>Note:</b>The returned KeyRecoveryObject does not contain a certificate. The caller
     * is responsible to search for the certificate based on the Issuer DN and Certificate Serial Number.
     * 
     * @param admin the administrator calling the function (used for audit logging)
     * @param username Username of the end entity
     * @param cryptoTokenId ID of crypto token to use to encrypt key.
     * @param keyAlias key alias in crypto token to use to encrypt key.
     * @return the marked keyrecovery data or null if none can be found. Note that the certificate property will be null.
     * 
     * @see KeyRecoverySession#recoverKeys
     */
    KeyRecoveryInformation recoverKeysInternal(AuthenticationToken admin, String username, int cryptoTokenId, String keyAlias);
    
    /**
     * Marks a users certificate for key recovery. This method performs no authorization checks and should only be called
     * when local key pair generation is used and checks has already been performed by the instance holding UserData in its
     * database
     * 
     * @param admin requesting administrator
     * @param certificate to be marked for recovery
     * @param username of the end entity related to certificate
     * @return true if flag was set in database successfully
     */
    boolean markAsRecoverableInternal(AuthenticationToken admin, CertificateWrapper certificate, String username);
}
