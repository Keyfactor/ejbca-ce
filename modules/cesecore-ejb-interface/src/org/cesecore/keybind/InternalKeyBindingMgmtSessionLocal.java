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
import java.util.List;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.pinning.TrustEntry;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * @see InternalKeyBindingMgmtSession
 * @version $Id$
 */
@Local
public interface InternalKeyBindingMgmtSessionLocal extends InternalKeyBindingMgmtSession {
       
    /**
     * Returns a list of all internal key bindings of a certain type, as {@link InternalKeyBindingInfo}s
     * 
     * @param internalKeyBindingType the key binding type
     * @return a list of all internal key bindings of that type, as {@link InternalKeyBindingInfo}s
     */
    List<InternalKeyBindingInfo> getAllInternalKeyBindingInfos(String internalKeyBindingType);
    
    /**
     * Internal (local only) method to get keybinding info without logging the authorization check
     * (the auth check is performed though).
     * 
     * @see getInternalKeyBindingInfo
     */
    InternalKeyBindingInfo getInternalKeyBindingInfoNoLog(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Get a reference to a cached InternalKeyBinding object that MAY NOT be modified.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the identifier of the InternalKeyBinding
     * @return the InternalKeyBinding for the requested Id or null if none was found
     * @throws AuthorizationDeniedException if the authentication token was not authorized to fetch the requested InternalKeyBinding
     */
    InternalKeyBinding getInternalKeyBindingReference(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Creates a list with {@link TrustEntry} instances according to the trust references defined by the internal key binding.
     * 
     * @param internalKeyBinding the internal key binding whose trust entries should be created.
     * @return a list of {@link TrustEntry} instances according to the trust references defined by the internal key binding.
     * @throws CADoesntExistsException if the internal key binding references a CA which has been removed.
     */
    List<TrustEntry> getTrustEntries(InternalKeyBinding internalKeyBinding) throws CADoesntExistsException;

    /**
     * Returns a id-to-name map of all internal key bindings of the given type 
     * 
     * @param internalKeyBindingType null for all types
     * @return id-name map of internal key bindings
     */
    Map<Integer, String> getAllInternalKeyBindingIdNameMap(String internalKeyBindingType);
    
    /**
     * Issue certificate for the internal key binding based on the enrollment information. This enrollment information
     * can only be provided from Configdump now and enrollment is only possible for key bindings present in a CA node.
     * 
     * @param authenticationToken
     * @param internalKeyBindingId
     * @param endEntityInformation
     * @param keySpec
     * 
     * @return
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws CertificateImportException
     */
    void issueCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId,
            EndEntityInformation endEntityInformation, String keySpec)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateCreateException, CertificateImportException;

    /**
     * Create an internal key binding with enrollment informations i.e. issuerDn, certifcateProfileName, endEntityProfileName
     * and optionally subjectDn. Currently used only with configdump and when the configdump is to be 'initialized' the
     * key binding is enrolled and set to active status by @see issueCertificateForInternalKeyBinding.
     * 
     * @param authenticationToken
     * @param type
     * @param id
     * @param name
     * @param status
     * @param certificateId
     * @param cryptoTokenId
     * @param keyPairAlias
     * @param allowMissingKeyPair
     * @param signatureAlgorithm
     * @param dataMap
     * @param trustedCertificateReferences
     * @param subjectDn
     * @param issuerDn
     * @param certificateProfileName
     * @param endEntityProfileName
     * @param keySpec
     * @return
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenOfflineException
     * @throws InternalKeyBindingNameInUseException
     * @throws InvalidAlgorithmException
     * @throws InternalKeyBindingNonceConflictException
     */
    int createInternalKeyBindingWithOptionalEnrollmentInfo(AuthenticationToken authenticationToken, String type, int id, String name,
            InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair,
            String signatureAlgorithm, Map<String, Serializable> dataMap, List<InternalKeyBindingTrustEntry> trustedCertificateReferences,
            String subjectDn, String issuerDn, String certificateProfileName, String endEntityProfileName, String keySpec)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException,
            InternalKeyBindingNonceConflictException;
}
