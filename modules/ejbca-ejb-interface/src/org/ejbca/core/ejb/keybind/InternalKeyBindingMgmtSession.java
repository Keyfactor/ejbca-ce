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
package org.ejbca.core.ejb.keybind;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Generic Management interface for InternalKeyBinding.
 * 
 * @version $Id$
 */
public interface InternalKeyBindingMgmtSession {

    /** @return a map where each entry is a registered implementation type and the value is a list of implementation specific properties for the type */
    Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> getAvailableTypesAndProperties(AuthenticationToken authenticationToken);

    /** @return a list of IDs for the specific type and that the caller is authorized to view */
    List<Integer> getInternalKeyBindingIds(AuthenticationToken authenticationToken, String internalKeyBindingType);

    // TODO: Move to local interface
    /** @return the InternalKeyBinding for the requested Id or null if none was found */
    InternalKeyBinding getInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /** @return the internalKeyBindingId from the more user friendly name. Return null of there is no such InternalKeyBinding. */
    Integer getIdFromName(String internalKeyBindingName);

    /** Creates a new InternalKeyBinding using the factory on the server side. */
    // TODO: Needs a signatureAlgorithm parameter
    int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, String name, InternalKeyBindingStatus status, String certificateId,
            int cryptoTokenId, String keyPairAlias, Map<Object, Object> dataMap) throws AuthorizationDeniedException, CryptoTokenOfflineException,
            InternalKeyBindingNameInUseException;

    /**
     * Create new (when the provided InternalKeyBinding has id 0) or merge existing InternalKeyBinding.
     * The caller must be authorized the modify the InternalKeyBinding and to CryptoTokenRules.USE the referenced CryptoToken.
     * @return the internalKeyBindingId that can be used for future reference if the object was created
     */
    int persistInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException;

    /** @return true if the InternalKeyBinding existed before deletion */
    boolean deleteInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;
    
    // TODO: We can probably make this local instead and only use it for internal renewal
    /**
     * @return the public key of the requested InternalKeyBinding in DER format 
     * @throws CryptoTokenOfflineException if the public key could not be retrieved from the referenced CryptoToken
     */
    byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /**
     * @return the a new PKCS#10 request for the InternalKeyBinding
     * @throws CryptoTokenOfflineException if the key pair is not available
     */
    byte[] generateCsrForNextKey(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException;

    /** 
     * Update the key mapping if there is a newer certificate in the database or a certificate matching the nextKey.
     * This could normally be used in a setup where the certificate is published or made available be other means
     * in the database for this EJBCA instance.
     * @return the Certificate's fingerprint if a change was made or null otherwise
     */
    String updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CertificateImportException, CryptoTokenOfflineException;

    /**
     * Imports the certificate provided in DER format to the database and updates the InternalKeyBinding reference.
     * If the the certificates public key matches the current instance's keyPairAlias, the keyPairAlias will not be updated.
     * If the nextKey property is set and the certificates public key matches, the instance's keyPairAlias will also be updated.
     * 
     * @throws CertificateImportException if the provided certificate's public key does not match current or next key. This is also
     * thrown if the implementation cannot validate that the certificate is of the right type.
     */
    void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] certificate)
        throws AuthorizationDeniedException, CertificateImportException;

    /**
     * Creates a new key pair with the same key specification as the current and a new alias.
     * @return the new key pair alias
     */
    String generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Issue a new certificate using the same end entity as the current certificate.
     * Note that this will only work as long as the CA is internal and the user and profiles still exist.
     * Since the user's current CA and profiles will be used, they could be changed before this call.
     * @return the newly issued certificate's fingerprint
     */
    String renewInternallyIssuedCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException;
    
    /**
     * Suitable for remote invocation where the implementation might not be available.
     * @return a list of InternalKeyBindings that extend a non-mutable general class.
     */
    List<InternalKeyBindingInfo> getInternalKeyBindingInfos(AuthenticationToken authenticationToken, String internalKeyBindingType);

    /**
     * Suitable for remote invocation where the implementation might not be available.
     * @return a list of InternalKeyBindings that extend a non-mutable general class.
     */
    InternalKeyBindingInfo getInternalKeyBindingInfo(AuthenticationToken authenticationToken, int id) throws AuthorizationDeniedException;

    /** @return true if the status was modified */
    boolean setStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus status)
            throws AuthorizationDeniedException;
}

