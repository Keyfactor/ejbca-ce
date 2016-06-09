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
package org.cesecore.keybind;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Generic Management interface for InternalKeyBinding.
 * 
 * @version $Id$
 */
public interface InternalKeyBindingMgmtSession {

    /** 
     * Get all registered InternalKeyBinding implementation and their properties.
     * 
     * @return a map where each entry is a registered implementation type and the value is a list of implementation specific properties for the type
     */
    Map<String, Map<String, DynamicUiProperty<? extends Serializable>>> getAvailableTypesAndProperties();
    
    /**
     * Get a list of all InternalKeyBindings of the requested type, regardless of authorization.
     * 
     * @param internalKeyBindingType is the identifier of the type of InternalKeyBinding
     * @return a list of IDs for the specific type and that the caller is authorized to view
     */
    List<Integer> getInternalKeyBindingIds(String internalKeyBindingType);
    
    /**
     * Get a list of all InternalKeyBindings the caller is authorized to view of the requested type.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingType is the identifier of the type of InternalKeyBinding
     * @return a list of IDs for the specific type and that the caller is authorized to view
     */
    List<Integer> getInternalKeyBindingIds(AuthenticationToken authenticationToken, String internalKeyBindingType);

    /**
     * Get a (cloned) InternalKeyBinding object. Use this method if you might change the object,
     * if the object is handled by an untrusted piece of code or if you are using Remote invocation.
     * 
     * (Otherwise, use {@link InternalKeyBindingMgmtSessionLocal#getInternalKeyBindingReference(AuthenticationToken, int)}
     * to avoid the unnecessary object creation.)
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the identifier of the InternalKeyBinding
     * @return the InternalKeyBinding for the requested Id or null if none was found
     * @throws AuthorizationDeniedException if the authentication token was not authorized to fetch the requested InternalKeyBinding
     */
    InternalKeyBinding getInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Get the InternalKeyBinding's identifier from a user friendly name.
     * 
     * @param internalKeyBindingName is the (unique) name of the InternalKeyBinding
     * @return the internalKeyBindingId from the more user friendly name. Return null of there is no such InternalKeyBinding.
     */
    Integer getIdFromName(String internalKeyBindingName);

    /** 
     * Creates a new InternalKeyBinding using the InternalKeyBindingFactory on the server side.
     * 
     * @param authenticationToken is the authentication token
     * @param type is the alias of the registered InternalKeyBinding's type
     * @param id is the id to use for the new InternalKeyBinding, or 0 for automatic choice
     * @param name is the unique name that this InternalKeyBinding will be given
     * @param status the initial status to give the InternalKeyBinding
     * @param certificateId is the certificate fingerprint matching the mapped key pair or null
     * @param cryptoTokenId is the CryptoToken id of the container where the mapped key pair is stored
     * @param keyPairAlias is the alias of the mapped key pair in the specified CryptoToken (may not be null)
     * @param allowMissingKeyPair if a missing key pair or crypto token should be allowed
     * @param signatureAlgorithm is the signature algorithm that this InternalKeyBinding will use for signatures (if applicable)
     * @param dataMap is a Map of implementation specific properties for this type of IntenalKeyBinding
     * @return the created InternalKeyBinding's unique identifier
     * 
     * @throws CryptoTokenOfflineException if the requested key pair was not accessible
     * @throws AuthorizationDeniedException if the authentication token was not authorized to create the InternalKeyBinding
     * @throws InternalKeyBindingNameInUseException if the requested name was already in use by another InternalKeyBinding
     * @throws InvalidAlgorithmException if the requested signature algorithm is not available
     */
    int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status, String certificateId,
            int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences)
                    throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException;
    
    /**
     * A createInternalKeyBinding() with allowMissingKeyPair=false
     * @see createInternalKeyBinding
     */
    int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, int id, String name, InternalKeyBindingStatus status, String certificateId,
            int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences)
                    throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException;

    /**
     * A createInternalKeyBinding() that chooses the id of the new object automatically.
     * @see createInternalKeyBinding
     */
    int createInternalKeyBinding(AuthenticationToken authenticationToken, String type, String name, InternalKeyBindingStatus status, String certificateId,
            int cryptoTokenId, String keyPairAlias, String signatureAlgorithm, Map<String, Serializable> dataMap,
            List<InternalKeyBindingTrustEntry> trustedCertificateReferences) throws AuthorizationDeniedException, CryptoTokenOfflineException,
            InternalKeyBindingNameInUseException, InvalidAlgorithmException;

    /**
     * Create new (when the provided InternalKeyBinding has id 0) or merge existing InternalKeyBinding.
     * The caller must be authorized the modify the InternalKeyBinding and to CryptoTokenRules.USE the referenced CryptoToken.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBinding is the InternalKeyBinding to persist
     * @return the internalKeyBindingId that can be used for future reference if the object was created
     * @throws AuthorizationDeniedException if the authentication token is not authorized to modify the InternalKeyBinding or use the CryptoToken
     * @throws InternalKeyBindingNameInUseException if the name is already in use by an InternalKeyBinding with a different id
     */
    int persistInternalKeyBinding(AuthenticationToken authenticationToken, InternalKeyBinding internalKeyBinding) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException;

    /**
     * Delete an InternalKeyBinding (this will not remove any referenced object like keys or certificates).
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique InternalKeyBinding identifier
     * @return true if the InternalKeyBinding existed before deletion
     * @throws AuthorizationDeniedException if the authentication token is not authorized to delete this InternalKeyBinding
     */
    boolean deleteInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;
    
    /**
     * Get the next key pair alias to use for renewals. If the next key field of the InternalKeyBinding is not set, the
     * current key pair alias will be returned instead.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @return the public key in DER format 
     * @throws AuthorizationDeniedException if the authentication token is not authorized to get this information
     * @throws CryptoTokenOfflineException if the public key could not be retrieved from the referenced CryptoToken
     */
    byte[] getNextPublicKeyForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /**
     * Generate a Certificate Signing Request (CSR) for the next key to be mapped by this InternalKeyBinging. If
     * no explicit "next" key exists a CSR for the current key will be returned (e.g. only renew cert, but not keys).
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @param name the subjectDN to be used in the CSR as binary encoded X500Name (X500Name.getEncoded), or null. If null the currently mapped certificate's SubjectDN will be used (if present) and if not a default (CN=Internal Key Binding Name), 
     * @return the a new PKCS#10 request for the InternalKeyBinding
     * @throws AuthorizationDeniedException is the authentication token is not authorized to this operation
     * @throws CryptoTokenOfflineException if the key pair is not available
     */
    byte[] generateCsrForNextKey(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] name) throws AuthorizationDeniedException, CryptoTokenOfflineException;

    /** 
     * Update the key mapping if there is a newer certificate in the database or a certificate matching the nextKey.
     * This could normally be used in a setup where the certificate is published or made available be other means
     * in the database for this EJBCA instance.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @return the certificate's fingerprint if a change was made or null otherwise
     * @throws AuthorizationDeniedException if the authentication token was not authorized to this operation
     * @throws CertificateImportException if the certificate could not be mapped (keys unavailable or wrong type of certificate)
     */
    String updateCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CertificateImportException;

    /**
     * Imports the certificate provided in DER format to the database and updates the InternalKeyBinding reference.
     * If the the certificates public key matches the current instance's keyPairAlias, the keyPairAlias will not be updated.
     * If the nextKey property is set and the certificates public key matches, the instance's keyPairAlias will also be updated.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @param certificate DER encoded certificate to import
     * @throws AuthorizationDeniedException if the authentication token was not authorized to this operation
     * @throws CertificateImportException if the provided certificate's public key does not match current or next key. This is also
     * thrown if the implementation cannot validate that the certificate is of the right type.
     */
    void importCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId, byte[] certificate)
        throws AuthorizationDeniedException, CertificateImportException;

    /**
     * Creates a new key pair with the same key specification as the current and a new alias.
     * If a nextKey reference already exists, it will be replaced with a reference to the new key.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @return the new key pair alias
     * @throws AuthorizationDeniedException if the authentication token was not authorized to this operation
     * @throws CryptoTokenOfflineException if the CryptoToken mapped by this InternalKeyBinding is not available
     * @throws InvalidKeyException if the current key spec could not be read and used properly
     * @throws InvalidAlgorithmParameterException if the current key algo could not be read and used properly
     */
    String generateNextKeyPair(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException;

    /**
     * Issue a new certificate using the same end entity as the current certificate.
     * Note that this will only work as long as the CA is internal and the user and profiles still exist.
     * Since the user's current CA and profiles will be used, they could be changed before this call.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @param endEntityInformation is the template to use for the renewal
     * @return the newly issued certificate's fingerprint
     * @throws AuthorizationDeniedException if the authentication token is not authorized to this operation
     * @throws CryptoTokenOfflineException if the mapped CryptoToken or keys are not available
     * @throws CertificateImportException if the newly issued certificate cannot be used with this InternalKeyBinding (e.g. the EEP might have changed)
     */
    String renewInternallyIssuedCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException;
    
    /**
     * Suitable for remote invocation where the implementation might not be available.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingType is the alias for a registered type of InternalKeyBindings
     * @return a list of authorized InternalKeyBindings that extend a non-mutable general class.
     */
    List<InternalKeyBindingInfo> getInternalKeyBindingInfos(AuthenticationToken authenticationToken, String internalKeyBindingType);

    /**
     * Suitable for remote invocation where the implementation might not be available.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @return a InternalKeyBindingInfo, or null if the key binding does not exist
     * @throws AuthorizationDeniedException of the authentication token is not authorized to this operation
     */
    InternalKeyBindingInfo getInternalKeyBindingInfo(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Update the status of the InternalKeyBinding. Note that it is not possible to enable an InternalKeyBinding that
     * has no certificate mapping.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the unique identifier of the InternalKeyBinding
     * @param status is one of org.cesecore.keybind.InternalKeyBindingStatus enum
     * @return true if the status was modified
     * @throws AuthorizationDeniedException of the authentication token is not authorized to this operation
     */
    boolean setStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus status) throws AuthorizationDeniedException;
}

