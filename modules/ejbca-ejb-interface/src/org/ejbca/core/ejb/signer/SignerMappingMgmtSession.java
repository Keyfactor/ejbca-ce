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
package org.ejbca.core.ejb.signer;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Generic Management interface for SignerMappings.
 * 
 * @version $Id$
 */
public interface SignerMappingMgmtSession {

    /** @return a list of IDs for SignerMappings of a specific type that the caller is authorized to view */
    List<Integer> getSignerMappingIds(AuthenticationToken authenticationToken, String signerMappingType);

    /** @return the SignerMapping for the requested Id or null if none was found */
    SignerMapping getSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException;

    /** @return the signerMappingId from the more user friendly name. Return null of there is no such SignerMapping. */
    Integer getIdFromName(String cryptoTokenName);

    /**
     * Create new (when the provided SignerMapper has id 0) or merge existing SignerMapping.
     * The caller must be authorized the modify the signerMapping id and to CryptoTokenRules.USE the referenced CryptoToken.
     * @return the signerMappingId
     */
    int persistSignerMapping(AuthenticationToken authenticationToken, SignerMapping signerMapping) throws AuthorizationDeniedException, SignerMappingNameInUseException;

    /** @return true if the SignerMapping existed before deletion */
    boolean deleteSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException;
    
    /**
     * @return the public key of the requested SignerMapping in DER format 
     * @throws CryptoTokenOfflineException if the public key could not be retrieved from the referenced CryptoToken
     */
    byte[] getNextPublicKeyForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    // The normal EJBCA way of doing it would be to just publish issued certificates.
    /** 
     * Update the key mapping if there is a newer certificate in the database or a certificate matching the nextKey.
     * This could normally be used in a setup where the certificate is published or made available be other means
     * in the database for this EJBCA instance.
     */
    void updateCertificateForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException,
            CertificateImportException, CryptoTokenOfflineException;

    /**
     * Imports the certificate provided in DER format to the database and updates the SignerMapping reference.
     * If the the certificates public key matches the current SignerMapping's keyPairAlias, the keyPairAlias will not be updated.
     * If the nextKey property is set and the certificates public key matches, the SignerMapping's keyPairAlias will also be updated.
     * 
     * @throws CertificateImportException if the provided certificate's public key does not match current or next key. This is also
     * thrown if the SignerMapping cannot validate that the certificate is of the right type.
     */
    void importCertificateForSignerMapping(AuthenticationToken authenticationToken, int signerMappingId, byte[] certificate)
        throws AuthorizationDeniedException, CertificateImportException;

    /** Creates a new key pair with the same key specification as the current and a new alias. */
    void generateNextKeyPair(AuthenticationToken authenticationToken, int signerMappingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;
}

