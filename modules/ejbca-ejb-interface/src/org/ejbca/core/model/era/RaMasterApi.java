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
package org.ejbca.core.model.era;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

/**
 * TODO: Implement with proper methods. Keep in mind that there is latency, so batch things.
 * 
 * @version $Id$
 */
public interface RaMasterApi {

    /** @return true if the implementation if the interface is available and usable. */
    boolean isBackendAvailable();
    
    /** Returns an AccessSet containing the access rules that are allowed for the given authentication token. */
    AccessSet getUserAccessSet(AuthenticationToken authenticationToken) throws AuthenticationFailedException;
    
    /** Gets multiple access sets at once. Returns them in the same order as in the parameter */
    List<AccessSet> getUserAccessSets(List<AuthenticationToken> authenticationTokens);

    /** @return a list with information about non-external CAs that the caller is authorized to see. */
    List<CAInfo> getAuthorizedCas(AuthenticationToken authenticationToken);

    /** @return the approval request with the given id, or null if it doesn't exist or if authorization was denied */
    RaApprovalRequestInfo getApprovalRequest(AuthenticationToken authenticationToken, int id);

    /** @return list of approval requests from the specified search criteria */
    RaRequestsSearchResponse searchForApprovalRequests(AuthenticationToken authenticationToken, RaRequestsSearchRequest raRequestsSearchRequest);
    
    /** @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise*/
    CertificateDataWrapper searchForCertificate(AuthenticationToken authenticationToken, String fingerprint);
    
    /** @return list of certificates from the specified search criteria*/
    RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest raCertificateSearchRequest);

    /** @return list of end entities from the specified search criteria*/
    RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken, RaEndEntitySearchRequest raEndEntitySearchRequest);

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCall(AuthenticationToken authenticationToken, String argument1, int argument2) throws AuthorizationDeniedException, EjbcaException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    /** @return map of authorized certificate profile Ids and each mapped name */
    Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /** @return map of authorized entity profile Ids and each mapped name */
    Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /** @return map of authorized end entity profiles for the provided authentication token */
    IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken);

    /** @return map of authorized and enabled CAInfos for the provided authentication token*/
    IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken);

    /** @return map of authorized certificate profiles for the provided authentication token*/
    IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken);
    
    /**
     * Adds (end entity) user.
     * @param admin authentication token
     * @param endEntity end entity data as EndEntityInformation object
     * @param clearpwd 
     * @throws AuthorizationDeniedException
     * @throws EjbcaException
     * @throws EndEntityExistsException if end entity already exists
     * @throws UserDoesntFullfillEndEntityProfile
     * @throws WaitingForApprovalException if approval is required to finalize the adding of the end entity
     * @throws CADoesntExistsException if CA doesn't exists
     */
    void addUser(AuthenticationToken admin, EndEntityInformation endEntity, boolean clearpwd) throws AuthorizationDeniedException, EjbcaException,
            EndEntityExistsException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException;

    /**
     * Generates keystore for the speicified end entity.
     * @param admin authentication token
     * @param endEntity holds end entity information (including user's password)
     * @param keyLength key length for non-EC or curve name for EC(etc. 1024, 2048,.. or brainpoolP224r1, prime239v1, secp 256k1,..)
     * @param keyAlg token key algorithm (DSA, ECDSA or RSA)
     * @return generated keystore
     * @throws AuthorizationDeniedException
     * @throws KeyStoreException if something went wrong with keystore creation
     */
    KeyStore generateKeystore(AuthenticationToken admin, EndEntityInformation endEntity, String keyLength, String keyAlg) throws AuthorizationDeniedException, KeyStoreException;
}
