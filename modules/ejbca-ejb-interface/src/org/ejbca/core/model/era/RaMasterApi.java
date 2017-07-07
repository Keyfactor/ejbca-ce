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

import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

/**
 * API of available methods on the CA that can be invoked by the RA.
 * 
 * Implementation restrictions:
 * - Keep in mind that there is latency, so batch things and don't for things twice unless it is expected to have change.
 * - Method names must be unique and signature is not allowed change after a release
 * - Any used object in this class must be Java Serializable
 * - Any used object in this class should be possible to use with an older or newer version of the peer
 * - Checked Exceptions are forwarded in full the implementation is responsible for not leaking sensitive information in
 *   nested causedBy exceptions.
 * 
 * @version $Id$
 */
public interface RaMasterApi {

    /** @return true if the implementation if the interface is available and usable. */
    boolean isBackendAvailable();
    
    /**
     * Get the current (lowest) back-end API version.
     * 
     * Note that this will not lead to a request over network since peers (if any) will report their API version when
     * connecting and this will return the cached and current number.
     * 
     * @return the current (lowest) back-end API version
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    int getApiVersion();

    /**
     * The AuthenticationToken is preliminary authorized to a resource if it is either
     * 1. authorized by the local system
     * 2. authorized by the remote system(s)
     * 
     * The local authorization system is always checked first and authorization is cached separately for local and remote system.
     * Since actual authorization check is performed during API call, a local override can never harm the remote system.
     * 
     * @return true if the authenticationToken is authorized to all the resources
     */
    boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String...resources);

    /**
     * @return the access rules and corresponding authorization system update number for the specified AuthenticationToken.
     * @throws AuthenticationFailedException if the provided authenticationToken is invalid
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    RaAuthorizationResult getAuthorization(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /**
     * Returns an AccessSet containing the access rules that are allowed for the given authentication token.
     * Note that AccessSets do not support deny rules.
     * @deprecated RA Master API version 1 (EJBCA 6.8.0). Use {@link #getAuthorization(AuthenticationToken)} instead.
     */
    @Deprecated
    AccessSet getUserAccessSet(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /**
     * Gets multiple access sets at once. Returns them in the same order as in the parameter.
     * Note that AccessSets do not support deny rules.
     * @deprecated RA Master API version 1 (EJBCA 6.8.0). Use {@link #getAuthorization(AuthenticationToken)} instead.
     */
    @Deprecated
    List<AccessSet> getUserAccessSets(List<AuthenticationToken> authenticationTokens);

    /** @return a list with information about non-external CAs that the caller is authorized to see. */
    List<CAInfo> getAuthorizedCas(AuthenticationToken authenticationToken);
    
    /**
     * @return a list with roles that the caller is authorized to see.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    List<Role> getAuthorizedRoles(AuthenticationToken authenticationToken);
    
    /**
     * @return the Role with the given ID, or null if it does not exist
     * @throws AuthorizationDeniedException if missing view access.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    Role getRole(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException;

    /**
     * @param roleId Only include namespaces from peers where this role is present. Set to 0 to include all.
     * @return a list of role namespaces the caller is authorized to see. Never returns null.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    List<String> getAuthorizedRoleNamespaces(AuthenticationToken authenticationToken, int roleId);
    
    /**
     * @return a list of token types and their match keys, which the caller is authorized to. Only user-configurable token types are returned.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    Map<String,RaRoleMemberTokenTypeInfo> getAvailableRoleMemberTokenTypes(AuthenticationToken authenticationToken);
    
    
    /**
     * Adds or updates a role in the database. If the role has an ID, it will be updated, but only on the system where it exists.
     * Otherwise, this method will try to create it on any of the configured systems.
     * @param authenticationToken Admin
     * @param role Role to persist. The roleId controls whether it should be added or updated.
     * @return The role object if the role was added/updated, otherwise null.
     * @throws AuthorizationDeniedException if unauthorized to update this role, or not authorized on any system to add it.
     * @throws RoleExistsException if a role with the given name already exists (can happen when adding or renaming)
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    Role saveRole(AuthenticationToken authenticationToken, Role role) throws AuthorizationDeniedException, RoleExistsException;

    /**
     * Deletes a role.
     * @param authenticationToken Administrator
     * @param roleId ID of role to delete.
     * @return true if the role was found and was deleted, and false if it didn't exist.
     * @throws AuthorizationDeniedException If unauthorized, or if trying to delete a role that the requesting admin belongs to itself.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    boolean deleteRole(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException;
    
    /**
     * @return the Role Member with the given ID, or null if it does not exist
     * @throws AuthorizationDeniedException if missing view access.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    RoleMember getRoleMember(AuthenticationToken authenticationToken, int roleMemberId) throws AuthorizationDeniedException;

    /**
     * Adds or updates a role member in the database. If the role member has an ID, it will be updated, but only on the system where it exists.
     * Otherwise, this method will try to create it on any of the configured systems.
     * @param authenticationToken Admin
     * @param roleMember RoleMember to persist. The roleMemberId controls whether it should be added or updated.
     * @return The role member object if the role member was added/updated, otherwise null.
     * @throws AuthorizationDeniedException if unauthorized to update this role member, or not authorized on any system to add it.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    RoleMember saveRoleMember(AuthenticationToken authenticationToken, RoleMember roleMember) throws AuthorizationDeniedException;
    
    /**
     * Removes a role member from a role.
     * @param authenticationToken Administrator
     * @param roleId ID of role (used as a safety check to prevent ID collisions).
     * @param roleMemberId ID of role member to delete.
     * @return true if the role member was found and was deleted, and false if it didn't exist.
     * @throws AuthorizationDeniedException If not authorized to edit the given role
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    boolean deleteRoleMember(AuthenticationToken authenticationToken, int roleId, int roleMemberId) throws AuthorizationDeniedException;
    
    /** @return the approval request with the given id, or null if it doesn't exist or if authorization was denied */
    RaApprovalRequestInfo getApprovalRequest(AuthenticationToken authenticationToken, int id);

    /**
     * Finds an approval by a hash of the request data.
     * 
     * @param approvalId Calculated hash of the request (this somewhat confusing name is re-used from the ApprovalRequest class)
     */
    RaApprovalRequestInfo getApprovalRequestByRequestHash(AuthenticationToken authenticationToken, int approvalId);
    
    /**
     * Modifies an approval request and sets the current admin as a blacklisted admin.
     * @return The new approval request (which may have a new id)
     */
    RaApprovalRequestInfo editApprovalRequest(AuthenticationToken authenticationToken, RaApprovalEditRequest edit) throws AuthorizationDeniedException;
    
    /**
     * Extends the validity of an approval request for the given amount of time. The status is set to Waiting for Approval if it was expired.
     * @param authenticationToken Admin
     * @param id Id of approval request
     * @param extendForMillis Milliseconds to extend the validity for
     * @throws IllegalStateException if the request is in approval or rejected state already.
     * @throws AuthorizationDeniedException If the admin does not have approval access to this request, e.g. due to missing access to CAs or missing approval access. 
     */
    void extendApprovalRequest(AuthenticationToken authenticationToken, int id, long extendForMillis) throws AuthorizationDeniedException;
    
    /** Approves, rejects or saves (not yet implemented) a step of an approval request. The action is determined by the "action" value in the given RaApprovalResponseRequest.
     * @return true if the approval request exists on this node, false if not.
     * @throws SelfApprovalException if trying to approve one's own action.
     * @throws AdminAlreadyApprovedRequestException if this approval request has been approved or rejected already.
     * @throws ApprovalRequestExecutionException if execution of the approval request (e.g. adding an end endity) failed.
     * @throws ApprovalRequestExpiredException if the approval request is older than the configured expiry time
     * @throws AuthenticationFailedException if the authentication token couldn't be validated
     * @throws ApprovalException is thrown for other errors, such as the approval being in the wrong state, etc.
     */
    boolean addRequestResponse(AuthenticationToken authenticationToken, RaApprovalResponseRequest requestResponse)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException, ApprovalRequestExecutionException,
            AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException;
    
    /**
     * Searches for approval requests.
     * @param authenticationToken administrator (affects the search results)
     * @param raRequestsSearchRequest specifies which requests to include (e.g. requests that can be approved by the given administrator)
     * @return list of approval requests from the specified search criteria
     */
    RaRequestsSearchResponse searchForApprovalRequests(AuthenticationToken authenticationToken, RaRequestsSearchRequest raRequestsSearchRequest);
    
    /** @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise*/
    CertificateDataWrapper searchForCertificate(AuthenticationToken authenticationToken, String fingerprint);
    
    /** @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise*/
    CertificateDataWrapper searchForCertificateByIssuerAndSerial(AuthenticationToken authenticationToken, String issuerDN, String serno);
    
    /** @return list of certificates from the specified search criteria*/
    RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest raCertificateSearchRequest);

    /** @return list of end entities from the specified search criteria*/
    RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken, RaEndEntitySearchRequest raEndEntitySearchRequest);

    /**
     * Searches for roles that the given authentication token has access to.
     * @param authenticationToken administrator (affects the search results)
     * @param raRoleSearchRequest Object specifying the search criteria.
     * @return Object containing list of roles and search status.
     */
    RaRoleSearchResponse searchForRoles(AuthenticationToken authenticationToken, RaRoleSearchRequest raRoleSearchRequest);
    
    /**
     * Searches for role members in all roles that the given authentication token has access to.
     * @param authenticationToken administrator (affects the search results)
     * @param raRoleMemberSearchRequest Object specifying the search criteria.
     * @return Object containing list of role members and search status.
     */
    RaRoleMemberSearchResponse searchForRoleMembers(AuthenticationToken authenticationToken, RaRoleMemberSearchRequest raRoleMemberSearchRequest);
    
    
    /** @return map of authorized certificate profile Ids and each mapped name */
    Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /** @return map of authorized entity profile Ids and each mapped name */
    Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /** @return map of authorized end entity profiles for the provided authentication token */
    IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken, String endEntityAccessRule);

    /** @return map of authorized and enabled CAInfos for the provided authentication token*/
    IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken);

    /** @return map of authorized certificate profiles for the provided authentication token*/
    IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken);
    
    /** @return CertificateProfile with the specified Id or null if it can not be found */
    CertificateProfile getCertificateProfile(int id);
    
    /**
     * Adds (end entity) user.
     * @param admin authentication token
     * @param endEntity end entity data as EndEntityInformation object
     * @param clearpwd 
     * @throws AuthorizationDeniedException
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws WaitingForApprovalException if approval is required to finalize the adding of the end entity
     * @return true if used has been added, false otherwise
     */
    boolean addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd) throws AuthorizationDeniedException,
    EjbcaException, WaitingForApprovalException;

    /**
     * Deletes (end entity) user. Does not propagate the exceptions but logs them.
     * @param authenticationToken
     * @param username the username of the end entity user about to delete
     * @throws AuthorizationDeniedException
     */
    void deleteUser(final AuthenticationToken authenticationToken, final String username) throws AuthorizationDeniedException;
    
    /**
     * Performs a finishUser operation after a key recovery operation. The end entity must be in NEW or KEYRECOVERY status
     * and the admin must have access to the CA of the end entity and key recovery access to the end entity profile. 
     * 
     * In detail this means:
     * Decrements the issue counter for an end entity, and sets the status to GENERATED when it reaches zero.
     * Usually this counter only goes from 1 to 0, so usually this method calls means "set end entity status to GENERATED".
     * When the status is set to GENERATED the password is also cleared.
     * 
     * @param authenticationToken authentication token 
     * @param username username of end entity
     * @param password password of end entity
     * @throws AuthorizationDeniedException if not authorized to perform key recovery for the given end entity
     * @throws EjbcaException if the user was not found or had the wrong status
     */
    void finishUserAfterLocalKeyRecovery(AuthenticationToken authenticationToken, String username, String password) throws AuthorizationDeniedException, EjbcaException;
    
    /**
     * Generates keystore for the specified end entity. Used for server side generated key pairs. It can be of PKCS12 or JKS type.
     * Keystore can be loaded with:
     *  
     * KeyStore ks = KeyStore.getInstance(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_SOFT_P12 ? "PKCS12" : "JKS");
     * ks.load(new ByteArrayInputStream(keystoreAsByteArray), endEntityInformation.getPassword().toCharArray());
     * 
     * Note that endEntityInformation are still needed to load a keystore.
     * @param authenticationToken authentication token
     * @param endEntityInformation holds end entity information (including user's password)
     * @return generated keystore
     * @throws AuthorizationDeniedException
     * @throws KeyStoreException if something went wrong with keystore creation
     */
    byte[] generateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException;

    /**
     * Generates certificate from CSR for the specified end entity. Used for client side generated key pairs.
     * @param authenticationToken authentication token
     * @param endEntity end entity information. CertificateRequest (CSR) must be set under extendedInformation of the endEntityInformation. 
     * @param certificateRequest CSR as PKCS10CertificateRequst object
     * @return certificate binary data. If the certificate request is invalid, then this can in certain cases be null.
     * @throws AuthorizationDeniedException
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     */
    byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException;

    /**
     * Generates a certificate. This variant is used from the Web Service interface.
     * @param authenticationToken authentication token.
     * @param userdata end entity information, encoded as a UserDataVOWS (web service value object). Must have been enriched by the WS setUserDataVOWS/enrichUserDataWithRawSubjectDn methods.
     * @param requestData see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param requestType see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param hardTokenSN see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param responseType see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @return certificate binary data. If the certificate request is invalid, then this can in certain cases be null. 
     * @throws AuthorizationDeniedException if not authorized to create a certificate with the given CA or the profiles
     * @throws ApprovalException if the request requires approval
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process, for example non-existent CA
     * @throws EndEntityProfileValidationException if the certificate does not match the profiles.
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest
     */
    byte[] createCertificateWS(final AuthenticationToken authenticationToken, final UserDataVOWS userdata, final String requestData, final int requestType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, ApprovalException, EjbcaException,
            EndEntityProfileValidationException;
    
    /**
     * Finds end entity by its username.
     * @param authenticationToken authentication token
     * @param username username of the end entity
     * @return end entity as EndEntityInformation
     */
    EndEntityInformation searchUser(AuthenticationToken authenticationToken, String username);

    /**
     * Gets the certificate chain for the most recently created certificate for the end entity with the given user name.
     * @param authenticationToken Authentication token.
     * @param username User name of end entity.
     * @return Certificate chain, with the leaf certificate first. If the users does not exist, it returns an empty list.
     * @throws AuthorizationDeniedException If not authorized to the end entity of the user
     * @throws EjbcaException On internal errors, such as badly encoded certificate.
     */
    List<CertificateWrapper> getLastCertChain(AuthenticationToken authenticationToken, String username)
            throws AuthorizationDeniedException, EjbcaException;
    
    /**
     * Request status change of a certificate (revoke or reactivate).
     * Requires authorization to CA, EEP for the certificate and '/ra_functionality/revoke_end_entity'.
     * 
     * @param authenticationToken of the requesting administrator or client
     * @param fingerprint of the certificate
     * @param newStatus CertificateConstants.CERT_REVOKED (40) or CertificateConstants.CERT_ACTIVE (20)
     * @param newRevocationReason One of RevokedCertInfo.REVOCATION_REASON_...
     * @return true if the operation was successful, false if the certificate could not be revoked for example since it did not exist
     * @throws ApprovalException if there was a problem creating the approval request
     * @throws WaitingForApprovalException if the request has been sent for approval
     */
    boolean changeCertificateStatus(AuthenticationToken authenticationToken, String fingerprint, int newStatus, int newRevocationReason)
            throws ApprovalException, WaitingForApprovalException;
    
    /**
     * Marks End entity for key recovery, sets a new enrollment code (used to enroll a new certificate) and marks KeyRecoveryData for recovery.
     * 
     * @param authenticationToken of the requesting administrator
     * @param username of end entity holding the certificate to recover
     * @param newPassword selected new password for key recovery
     * @param cert Certificate to be recovered
     * @return true if key recovery was successful. False should not be returned unless unexpected error occurs. Other cases such as required approval
     * should throw exception instead
     * @throws AuthorizationDeniedException if administrator isn't authorized to operations carried out during key recovery preparations
     * @throws ApprovalException if key recovery is already awaiting approval
     * @throws CADoesntExistsException if CA which enrolled the certificate no longer exists
     * @throws WaitingForApprovalException if operation required approval (expected to be thrown with approvals enabled)
     * @throws NoSuchEndEntityException if End Entity bound to certificate no longer exists
     * @throws EndEntityProfileValidationException if End Entity doesn't match profile
     */
    boolean markForRecovery(AuthenticationToken authenticationToken, String username, String newPassword, CertificateWrapper cert, boolean localKeyGeneration) throws AuthorizationDeniedException, ApprovalException, 
                            CADoesntExistsException, WaitingForApprovalException, NoSuchEndEntityException, EndEntityProfileValidationException;
    
    /**
     * Checks if key recovery is possible for the given parameters. Requesting administrator has be authorized to perform key recovery
     * and authorized to perform key recovery on the End Entity Profile which the End Entity belongs to.
     * KeyRecoverData has to be present in the database for the given certificate, 
     * 
     * @param authenticationToken of the requesting administrator
     * @param cert Certificate to be recovered
     * @param username which the certificate is bound to
     * @return true if key recovery is possible given the parameters
     */
    boolean keyRecoveryPossible(AuthenticationToken authenticationToken, Certificate cert, String username);
    
    /**
     * Gets approval profile for specified action.
     * @param authenticationToken auth. token to be checked if it has access to the specified caInfo and certificateProfile
     * @param action a ApprovalRequestType constant
     * @param caId id of specified CA
     * @param certificateProfileId id of specified certificate profile
     * @return approval profile if it is required for specified caInfo and certificateProfile, null if it is not
     * @throws AuthorizationDeniedException if authentication token is not authorized to specified CA or certificate profile
     */
    public ApprovalProfile getApprovalProfileForAction(final AuthenticationToken authenticationToken, final ApprovalRequestType action, final int caId, final int certificateProfileId) throws AuthorizationDeniedException;

    /**
     * Performs all "deep" checks of user data (EndEntityInformation) intended to be added. Checks like uniqueness of SubjectDN or username should be part of this test.
     * @param authenticationToken auth. token
     * @param endEntity user data as EndEntityInformation object
     * @throws AuthorizationDeniedException if authentication token is not authorized to perform checks on user data
     * @throws EjbcaException exception with errorCode if check fails
     */
    void checkSubjectDn(AuthenticationToken admin, EndEntityInformation endEntity) throws AuthorizationDeniedException, EjbcaException;

    void checkUserStatus(AuthenticationToken authenticationToken, String username, String password) throws NoSuchEndEntityException, AuthStatusException, AuthLoginException;

    /**
     * Dispatch CMP request over RaMasterApi.
     * 
     * Basic ASN.1 validation is performed at a proxy to increase the protection of a CA slightly.
     * 
     * @param authenticationToken the origin of the request
     * @param pkiMessageBytes the ASN.1 encoded CMP message request bytes
     * @param cmpConfigurationAlias the requested CA configuration that should handle the request.
     * @return the CMP response ASN.1 (success or error) message as a byte array or null if no processing could take place
     * @see CmpMessageDispatcherSessionLocal#dispatchRequest(AuthenticationToken, byte[], String)
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    byte[] cmpDispatch(AuthenticationToken authenticationToken, byte[] pkiMessageBytes, String cmpConfigurationAlias) throws NoSuchAliasException;
}
