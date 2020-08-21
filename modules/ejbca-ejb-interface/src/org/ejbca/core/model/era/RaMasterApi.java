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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.CesecoreException;
import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
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
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.core.protocol.acme.AcmeAccount;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;
import org.ejbca.util.query.IllegalQueryException;

/**
 * API of available methods on the CA that can be invoked by the RA.
 *
 * <p>Implementation restrictions:
 *
 * <ul>
 * <li> Keep in mind that there is latency, so batch things and don't for things twice unless it is expected to have change.
 * <li> Method names must be unique and signature is not allowed change after a release
 * <li> Any used object in this class must be Java Serializable
 * <li> Any used object in this class should be possible to use with an older or newer version of the peer
 * <li> Checked Exceptions are forwarded in full the implementation is responsible for not leaking sensitive information in
 *   nested causedBy exceptions.
 * <li> Query both local and remote, when applicable. Usually, local should be queried first for best performance.
 * <li> Avoid having WS or REST-specific operations here (sometimes this is hard to avoid)
 * <li> Try to put complex business logic into "business logic EJBs" such as CaSession etc. rather than here.
 * <li> Remember to put @since attributes on new methods.
 * </ul>
 *
 * <p>See the "RA Master API conventions" page in Confluence for more detailed information.
 *
 */
public interface RaMasterApi {

    /**
     * @return true if the implementation if the interface is available and usable.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
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
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String...resources);

    /**
     * @return the access rules and corresponding authorization system update number for the specified AuthenticationToken.
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    RaAuthorizationResult getAuthorization(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /**
     * Returns an AccessSet containing the access rules that are allowed for the given authentication token.
     * Note that AccessSets do not support deny rules.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     * @deprecated RA Master API version 1 (EJBCA 6.8.0). Use {@link #getAuthorization(AuthenticationToken)} instead.
     */
    @Deprecated
    AccessSet getUserAccessSet(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    /**
     * Gets multiple access sets at once. Returns them in the same order as in the parameter.
     * Note that AccessSets do not support deny rules.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     * @deprecated RA Master API version 1 (EJBCA 6.8.0). Use {@link #getAuthorization(AuthenticationToken)} instead.
     */
    @Deprecated
    List<AccessSet> getUserAccessSets(List<AuthenticationToken> authenticationTokens);

    /**
     * @return a list with information about non-external CAs that the caller is authorized to see.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    List<CAInfo> getAuthorizedCas(AuthenticationToken authenticationToken);

    /**
     * Retrieves a list of all custom style archives
     * @param authenticationToken of the requesting administrator
     * @return List of all style archives or null if no styles were found
     * @throws AuthorizationDeniedException if requesting administrator is unauthorized to style archives
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.10.0), lacks an exact API version
     */
    LinkedHashMap<Integer, RaStyleInfo> getAllCustomRaStyles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException;

    /**
     * Returns a list of all style archives associated to roles which the requesting administrator is member of.
     * @param authenticationToken of the requesting administrator
     * @param hashCodeOfCurrentList will be compared with RaStyleInfos. If equal, null is returned to avoid heavy network traffic. Set 0 to ignore.
     * @return list of associated style archives. Empty list if administrator is not a member of any role or if role has no custom styles applied. Null if
     * hashCodeOfCurrentList matched, hence doesn't require an update
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.10.0), lacks an exact API version
     */
    List<RaStyleInfo> getAvailableCustomRaStyles(AuthenticationToken authenticationToken, int hashCodeOfCurrentList);

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

    /**
     * @return the approval request with the given id, or null if it doesn't exist or if authorization was denied
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaApprovalRequestInfo getApprovalRequest(AuthenticationToken authenticationToken, int id);

    /**
     * Finds an approval by a hash of the request data.
     *
     * @param approvalId Calculated hash of the request (this somewhat confusing name is re-used from the ApprovalRequest class)
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaApprovalRequestInfo getApprovalRequestByRequestHash(AuthenticationToken authenticationToken, int approvalId);

    /**
     * Modifies an approval request and sets the current admin as a blacklisted admin.
     * @return The new approval request (which may have a new id)
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaApprovalRequestInfo editApprovalRequest(AuthenticationToken authenticationToken, RaApprovalEditRequest edit) throws AuthorizationDeniedException;

    /**
     * Extends the validity of an approval request for the given amount of time. The status is set to Waiting for Approval if it was expired.
     * @param authenticationToken Admin
     * @param id Id of approval request
     * @param extendForMillis Milliseconds to extend the validity for
     * @throws IllegalStateException if the request is in approval or rejected state already.
     * @throws AuthorizationDeniedException If the admin does not have approval access to this request, e.g. due to missing access to CAs or missing approval access.
     * @since Added between the Initial RA Master API version and version 1 (EJBCA 6.7.0), lacks an exact API version
     */
    void extendApprovalRequest(AuthenticationToken authenticationToken, int id, long extendForMillis) throws AuthorizationDeniedException;

    /** Approves, rejects or saves (not yet implemented) a step of an approval request. The action is determined by the "action" value in the given RaApprovalResponseRequest.
     * @return true if the approval request exists on this node, false if not.
     * @throws SelfApprovalException if trying to approve one's own action.
     * @throws AdminAlreadyApprovedRequestException if this approval request has been approved or rejected already.
     * @throws ApprovalRequestExecutionException if execution of the approval request (e.g. adding an end entity) failed.
     * @throws ApprovalRequestExpiredException if the approval request is older than the configured expiry time
     * @throws AuthenticationFailedException if the authentication token couldn't be validated
     * @throws ApprovalException is thrown for other errors, such as the approval being in the wrong state, etc.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    boolean addRequestResponse(AuthenticationToken authenticationToken, RaApprovalResponseRequest requestResponse)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException, ApprovalRequestExecutionException,
            AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException;

    /**
     * Searches for approval requests.
     * @param authenticationToken administrator (affects the search results)
     * @param raRequestsSearchRequest specifies which requests to include (e.g. requests that can be approved by the given administrator)
     * @return list of approval requests from the specified search criteria
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaRequestsSearchResponse searchForApprovalRequests(AuthenticationToken authenticationToken, RaRequestsSearchRequest raRequestsSearchRequest);

    /**
     * Searches for a certificate. If present locally, then the data (revocation status etc.) from the local database will be returned
     * @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    CertificateDataWrapper searchForCertificate(AuthenticationToken authenticationToken, String fingerprint);

    /**
     * Searches for a certificate. If present locally, then the data (revocation status etc.) from the local database will be returned.
     * Returns a certificate and its Ca chain
     * @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise
     * @since Initial RA Master API version (EJBCA 7.4.2)
     */
    List<CertificateWrapper> searchForCertificateChain(AuthenticationToken authenticationToken, String fingerprint);

    /**
     * Searches for a certificate. If present locally, then the data (revocation status etc.) from the local database will be returned
     * @return CertificateDataWrapper if it exists and the caller is authorized to see the data or null otherwise
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.9.0), lacks an exact API version
     */
    CertificateDataWrapper searchForCertificateByIssuerAndSerial(AuthenticationToken authenticationToken, String issuerDN, String serNo);

    /**
     * Searches for certificates. Data (e.g. revocation status) of remote certificates take precedence over local ones.
     * @return list of certificates from the specified search criteria
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest raCertificateSearchRequest);

    /**
     * Searches for end entities. Remote end entities take precedence over local ones.
     * @return list of end entities from the specified search criteria
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken, RaEndEntitySearchRequest raEndEntitySearchRequest);

    /**
     * Searches for roles that the given authentication token has access to.
     * @param authenticationToken administrator (affects the search results)
     * @param raRoleSearchRequest Object specifying the search criteria.
     * @return Object containing list of roles and search status.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    RaRoleSearchResponse searchForRoles(AuthenticationToken authenticationToken, RaRoleSearchRequest raRoleSearchRequest);

    /**
     * Searches for role members in all roles that the given authentication token has access to.
     * @param authenticationToken administrator (affects the search results)
     * @param raRoleMemberSearchRequest Object specifying the search criteria.
     * @return Object containing list of role members and search status.
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    RaRoleMemberSearchResponse searchForRoleMembers(AuthenticationToken authenticationToken, RaRoleMemberSearchRequest raRoleMemberSearchRequest);


    /**
     * @return map of authorized certificate profile Ids and each mapped name
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /**
     * @return map of authorized entity profile Ids and each mapped name
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken);

    /**
     * @return map of authorized end entity profiles for the provided authentication token
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken, String endEntityAccessRule);

    /**
     * @return map of authorized and enabled CAInfos for the provided authentication token
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken);

    /**
     * @return map of authorized certificate profiles for the provided authentication token
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken);

    /**
     * @return CertificateProfile with the specified Id or null if it can not be found
     * @since Master RA API version 1 (EJBCA 6.8.0)
     */
    CertificateProfile getCertificateProfile(int id);

    /**
     * Adds (end entity) user.
     * @param authenticationToken authentication token
     * @param endEntity end entity data as EndEntityInformation object
     * @param isClearPwd true if the password will be stored in clear form in the db, otherwise it is hashed.
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws WaitingForApprovalException if approval is required to finalize the adding of the end entity. The request ID will be included as a field in this exception.
     * @return true if used has been added, false otherwise
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    boolean addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean isClearPwd) throws AuthorizationDeniedException,
    EjbcaException, WaitingForApprovalException;

    /**
     * addUserFromWS is called from EjbcaWS if profile specifies merge data from
     * profile to user we merge them before calling addUser
     *
     * @param authenticationToken the administrator performing the action
     * @param userData a UserDataVOWS object from WS
     * @param isClearPwd true if the password will be stored in clear form in the db, otherwise it is hashed.
     *
     * @return true if used has been added, false otherwise
     *
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws EndEntityProfileValidationException if data doesn't fulfill requirements of end entity profile
     * @throws EndEntityExistsException  if user already exists or some other database error occur during commit
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue. The request ID will be included as a field in this exception.
     * @throws CADoesntExistsException if the caId of the user does not exist
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws ApprovalException if an approval already exists for this request.
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws EjbcaException if userData couldn't be converted to an EndEntityInformation
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    boolean addUserFromWS(AuthenticationToken authenticationToken, UserDataVOWS userData, boolean isClearPwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, CustomFieldException, IllegalNameException, ApprovalException, CertificateSerialNumberException, EjbcaException;

    /**
     * Deletes (end entity) user. Does not propagate the exceptions but logs them.
     * @param authenticationToken authentication token
     * @param username the username of the end entity user about to delete
     * @throws AuthorizationDeniedException if administrator isn't authorized to delete user
     * @since Initial RA Master API version (EJBCA 6.6.0)
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
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.9.0), lacks an exact API version
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
     * @throws AuthorizationDeniedException if not authorized
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    byte[] generateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException;

    /**
     * Generates certificate from CSR for the specified end entity. Used for client side generated key pairs.
     * @param authenticationToken authentication token
     * @param endEntity end entity information. CertificateRequest (CSR) must be set under extendedInformation of the endEntityInformation.
     * @return certificate binary data. If the certificate request is invalid, then this can in certain cases be null.
     * @throws AuthorizationDeniedException if not authorized
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException;

    /**
     * Adds (end entity) user and generates certificate from CSR for this end entity. Used for client side generated key pairs.
     * @param authenticationToken authentication token
     * @param endEntity end entity information. CertificateRequest (CSR) must be set under extendedInformation of the endEntityInformation.
     * @param isClearPwd should password be stored in clear way(true) or hashed (false)
     * @return certificate binary data. If the certificate request is invalid, then this can in certain cases be null.
     * @throws AuthorizationDeniedException if not authorized
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    byte[] addUserAndCreateCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean isClearPwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException;
    /**
     * Adds (end entity) user and generates keystore for this end entity. Used to enroll certificate from RA. It can be of PKCS12 or JKS type.
     * Keystore can be loaded with:
     *
     * KeyStore ks = KeyStore.getInstance(endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_SOFT_P12 ? "PKCS12" : "JKS");
     * ks.load(new ByteArrayInputStream(keystoreAsByteArray), endEntityInformation.getPassword().toCharArray());
     * @param authenticationToken authentication token
     * @param endEntity end entity data as EndEntityInformation object
     * @param isClearPwd should password be stored in clear way(true) or hashed (false)
     * @throws AuthorizationDeniedException if not authorized
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws WaitingForApprovalException if approval is required to finalize the adding of the end entity. The request ID will be included as a field in this exception.
     * @return generated keystore. If the provided data is invalid, then this can in certain cases be null.
     * @since Initial RA Master API version (EJBCA 6.14.0)
     */
    byte[] addUserAndGenerateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean isClearPwd) throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException;

    /**
     * Generates a certificate. This variant is used from the Web Service interface.
     * @param authenticationToken authentication token.
     * @param userData end entity information, encoded as a UserDataVOWS (web service value object). Must have been enriched by the WS setUserDataVOWS/enrichUserDataWithRawSubjectDn methods.
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
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    byte[] createCertificateWS(final AuthenticationToken authenticationToken, final UserDataVOWS userData, final String requestData, final int requestType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, EjbcaException,
            EndEntityProfileValidationException;

    /**
     * Enrolls a new end entity and creates an SSH certificate according to the profiles defined for that end entity
     *
     * @param authenticationToken an authentication token
     * @param userDataVOWS a {@link UserDataVOWS} object describing the end entity to be created
     * @param sshRequestMessage a {@link SshRequestMessage} container with the request details
     *
     * @return an SSH encoded certificate
     *
     * @throws AuthorizationDeniedException if not authorized to create a certificate with the given CA or the profiles
     * @throws EndEntityProfileValidationException if the certificate does not match the profiles.
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process, for example non-existent CA
     * @throws ApprovalException if the request requires approval
     * @since RA Master API version 9 (EJBCA 7.4.1)
     */
    byte[] enrollAndIssueSshCertificateWs(AuthenticationToken authenticationToken, UserDataVOWS userDataVOWS, SshRequestMessage sshRequestMessage)
            throws AuthorizationDeniedException, ApprovalException, EjbcaException, EndEntityProfileValidationException;

    /**
     * Generates a certificate. This variant is used from the REST Service interface.
     * @param authenticationToken authentication token.
     * @param enrollCertificateRequest input data object for enrolling a certificate
     * @throws CertificateProfileDoesNotExistException if no profile was found
     * @throws CADoesntExistsException if the CA doesn't exist
     * @throws AuthorizationDeniedException if not authorized
     * @throws EndEntityProfileNotFoundException if EEP not found
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws EndEntityProfileValidationException if End Entity doesn't match profile
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    byte[] createCertificateRest(AuthenticationToken authenticationToken, EnrollPkcs10CertificateRequest enrollCertificateRequest)
            throws CertificateProfileDoesNotExistException, CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileNotFoundException,
            EjbcaException, EndEntityProfileValidationException;


    /**
     * Finds end entity by its username.
     * @param authenticationToken authentication token
     * @param username username of the end entity
     * @return end entity as EndEntityInformation
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    EndEntityInformation searchUser(AuthenticationToken authenticationToken, String username);

    /**
     * Gets the certificate chain for the most recently created certificate for the end entity with the given user name.
     * @param authenticationToken Authentication token.
     * @param username User name of end entity.
     * @return Certificate chain, with the leaf certificate first. If the users does not exist, it returns an empty list.
     * @throws AuthorizationDeniedException If not authorized to the end entity of the user
     * @throws EjbcaException On internal errors, such as badly encoded certificate.
     * @since RA Master API version 1 (EJBCA 6.8.0)
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
     * @throws WaitingForApprovalException if the request has been sent for approval. The request ID will be included as a field in this exception.
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    boolean changeCertificateStatus(AuthenticationToken authenticationToken, String fingerprint, int newStatus, int newRevocationReason)
            throws ApprovalException, WaitingForApprovalException;

    /**
     * @see EndEntityManagementSessionLocal#revokeCert(AuthenticationToken, BigInteger, Date, String, int, boolean)
     * @throws CADoesntExistsException in addition to the above throws if the CA (from issuer DN) is not handled by this instance, fail-fast
     * @since RA Master API version 3 (EJBCA 6.12.0)
     */
    void revokeCert(AuthenticationToken authenticationToken, BigInteger certSerNo, Date revocationDate, String issuerDn, int reason, boolean checkDate)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException;

    /**
     * Request status change of a certificate (revoke or reactivate).
     * Requires authorization to CA, EEP for the certificate and '/ra_functionality/revoke_end_entity'.
     * Difference with normal RevokeCertCommand is that
     * this one here allows to include reason, certificateProfileId and revocation date as input parameters wrapped into CertRevocationDto dto class
     *
     * @param authenticationToken of the requesting administrator or client
     * @param certRevocationDto wrapper objects for input parameters for the revoke
     *
     * @throws AuthorizationDeniedException if not authorized
     * @throws NoSuchEndEntityException if certificate to revoke can not be found
     * @throws ApprovalException if revocation has been requested and is waiting for approval.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception.
     * @throws RevokeBackDateNotAllowedForProfileException if certificate profile is not allowing revocation back date.
     * @throws AlreadyRevokedException if a revocation request for an already revoked object is requested
     * @throws CADoesntExistsException in addition to the above throws if the CA (from issuer DN) is not handled by this instance, fail-fast
     * @throws CertificateProfileDoesNotExistException if no profile was found with certRevocationDto.certificateProfileId input parameter.
     * @since Added between Master RA API version 3 and 4 (EJBCA 6.13.0), lacks an exact API version
     */
    void revokeCertWithMetadata(AuthenticationToken authenticationToken, CertRevocationDto certRevocationDto)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException, IllegalArgumentException,
            CertificateProfileDoesNotExistException;

    /**
     * Revokes all of a user's certificates. A revocation must succeed at least on one instance, otherwise the operation fails with an exception.
     *
     * @see EndEntityManagementSessionLocal#revokeUser(AuthenticationToken, String, int, boolean)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    void revokeUser(AuthenticationToken authenticationToken, String username, int reason, boolean deleteUser) throws AuthorizationDeniedException, CADoesntExistsException,
            WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException, EjbcaException;

    /**
     * @see CertificateStoreSession#getStatus(String, BigInteger)
     * @throws CADoesntExistsException in addition to the above throws if the CA (from issuer DN) is not handled by this instance, fail-fast
     * @throws AuthorizationDeniedException in addition to the above throws if caller is not authorized to revoke certificates from the CA (from issuer DN)
     * @since RA Master API version 3 (EJBCA 6.12.0)
     */
    CertificateStatus getCertificateStatus(AuthenticationToken authenticationToken, String issuerDn, BigInteger serNo) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Marks End entity for key recovery, sets a new enrollment code (used to enroll a new certificate) and marks KeyRecoveryData for recovery.
     *
     * @param authenticationToken of the requesting administrator
     * @param username of end entity holding the certificate to recover
     * @param newPassword selected new password for key recovery. May be null (e.g. in a call from EjbcaWS)
     * @param cert Certificate to be recovered
     * @return true if key recovery was successful. False should not be returned unless unexpected error occurs. Other cases such as required approval
     * should throw exception instead
     * @throws AuthorizationDeniedException if administrator isn't authorized to operations carried out during key recovery preparations
     * @throws ApprovalException if key recovery is already awaiting approval
     * @throws CADoesntExistsException if CA which enrolled the certificate no longer exists
     * @throws WaitingForApprovalException if operation required approval (expected to be thrown with approvals enabled). The request ID will be included as a field in this exception.
     * @throws NoSuchEndEntityException if End Entity bound to certificate isn't found.
     * @throws EndEntityProfileValidationException if End Entity doesn't match profile
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.9.0), lacks an exact API version
     */
    boolean markForRecovery(AuthenticationToken authenticationToken, String username, String newPassword, CertificateWrapper cert, boolean localKeyGeneration) throws AuthorizationDeniedException, ApprovalException,
                            CADoesntExistsException, WaitingForApprovalException, NoSuchEndEntityException, EndEntityProfileValidationException;

    /**
     * Edit End Entity information. Can only be used with API version 2 and later.
     *
     * @param authenticationToken the administrator performing the action
     * @param endEntityInformation an EndEntityInformation object with the new information
     * @param isClearPwd true if the password will be stored in clear form in the  db, otherwise it is hashed.
     * @throws AuthorizationDeniedException administrator not authorized to edit user
     * @throws EndEntityProfileValidationException data doesn't fulfill EEP requirements
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if the action has been added in the approval queue. The request ID will be included as a field in this exception.
     * @throws CADoesntExistsException if the user's CA doesn't exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists
     * @throws NoSuchEndEntityException if the EE was not found
     * @throws CustomFieldException if the EE was not validated by a locally defined field validator
     * @since RA Master API version 2 (EJBCA 6.11.0)
     */
    boolean editUser(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation, boolean isClearPwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException;

    /**
     * Edit End Entity information (version for EjbcaWS, that takes a UserDataVOWS)
     *
     * @param authenticationToken the administrator performing the action
     * @param userDataVOWS an UserDataVOWS object with the new information
     * @throws AuthorizationDeniedException administrator not authorized to edit user
     * @throws EndEntityProfileValidationException data doesn't fulfill EEP requirements
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws WaitingForApprovalException if the action has been added in the approval queue. The request ID will be included as a field in this exception.
     * @throws CADoesntExistsException if the user's CA doesn't exist
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists
     * @throws NoSuchEndEntityException if the EE was not found
     * @throws CustomFieldException if the EE was not validated by a locally defined field validator
     * @throws EjbcaException if userDataVOWS couldn't be converted to an EndEntityInformation
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    boolean editUserWs(AuthenticationToken authenticationToken, UserDataVOWS userDataVOWS)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException, EjbcaException;

    /**
     * Key recovery method to be called from web services. This method handles some special cases differently from the regular key recovery method.
     *
     * @param authenticationToken of the requesting administrator
     * @param username of end entity holding the certificate to recover
     * @param certSNinHex of the certificate to recover
     * @param issuerDN which issued the certificate
     * @throws AuthorizationDeniedException if administrator isn't authorized to operations carried out during key recovery preparations
     * @throws EjbcaException wrapped exceptions caught in EjbcaWS
     * @throws WaitingForApprovalException if operation required approval (expected to be thrown with approvals enabled). The request ID will be included as a field in this exception.
     * @throws ApprovalException if an approval is already pending to recover this certificate
     * @throws CADoesntExistsException if CA which enrolled the certificate no longer exists
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.9.0), lacks an exact API version
     */
    void keyRecoverWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN) throws AuthorizationDeniedException, EjbcaException,
                        WaitingForApprovalException, ApprovalException, CADoesntExistsException;

    /**
     * Atomic Key recovery and PKCS12 / JKS enrollment method to be called from web services.
     * @param authenticationToken of the requesting administrator
     * @param username of end entity holding the certificate to recover
     * @param certSNinHex of the certificate to recover
     * @param issuerDN issuer of the certificate
     * @param password new
     * @param hardTokenSN see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @return KeyStore generated, post recovery
     * @throws AuthorizationDeniedException if administrator isn't authorized to operations carried out during key recovery and enrollment
     * @throws WaitingForApprovalException if operation requires approval (expected to be thrown with approvals enabled). The request ID will be included as a field in this exception.
     * @throws EjbcaException exception with errorCode if check fails
     * @throws CADoesntExistsException if CA which issued the certificate no longer exists
     * @throws ApprovalException if an approval is already pending to recover this certificate
     * @since RA Master API version 3 (EJBCA 6.12.0)
     */
    byte[] keyRecoverEnrollWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN, String password,
            String hardTokenSN) throws AuthorizationDeniedException, ApprovalException, CADoesntExistsException, EjbcaException, WaitingForApprovalException;

    /**
     * Checks if key recovery is possible for the given parameters. Requesting administrator has be authorized to perform key recovery
     * and authorized to perform key recovery on the End Entity Profile which the End Entity belongs to.
     * KeyRecoverData has to be present in the database for the given certificate,
     *
     * @param authenticationToken of the requesting administrator
     * @param cert Certificate to be recovered
     * @param username which the certificate is bound to
     * @return true if key recovery is possible given the parameters
     * @since Added between Master RA API version 1 and 2 (EJBCA 6.9.0), lacks an exact API version
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
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    ApprovalProfile getApprovalProfileForAction(final AuthenticationToken authenticationToken, final ApprovalRequestType action, final int caId, final int certificateProfileId) throws AuthorizationDeniedException;

    /**
     * Performs all "deep" checks of user data (EndEntityInformation) intended to be added. Checks like uniqueness of SubjectDN or username should be part of this test.
     * @param admin auth. token
     * @param endEntity user data as EndEntityInformation object
     * @throws AuthorizationDeniedException if authentication token is not authorized to perform checks on user data
     * @throws EjbcaException exception with errorCode if check fails
     * @since Initial RA Master API version (EJBCA 6.6.0)
     */
    void checkSubjectDn(AuthenticationToken admin, EndEntityInformation endEntity) throws AuthorizationDeniedException, EjbcaException;

    /**
     * @see EndEntityAuthenticationSessionLocal#authenticateUser(AuthenticationToken, String, String)
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    void checkUserStatus(AuthenticationToken authenticationToken, String username, String password) throws NoSuchEndEntityException, AuthStatusException, AuthLoginException;


    /**
     * Dispatch SCEP message over RaMasterApi.
     *
     * @param authenticationToken the origin of the request
     * @param operation desired SCEP operation to perform
     * @param message to dispatch
     * @param scepConfigurationAlias name of alias containing SCEP configuration
     * @return byte array containing dispatch response from CA. Content depends on operation
     * @throws CertificateEncodingException if an error occurs while attempting to encode a certificate.
     * @throws NoSuchAliasException if the alias doesn't exist
     * @throws CADoesntExistsException if the CA doesn't exist
     * @throws NoSuchEndEntityException if an end entity is thought to exist but does not
     * @throws CustomCertificateSerialNumberException if we use custom certificate serial numbers, but are not using a unique issuerDN/certSerialNo index in the database
     * @throws CryptoTokenOfflineException if we use a CA Token that isn't available
     * @throws IllegalKeyException if malformed key
     * @throws SignRequestException if malformed certificate request.
     * @throws SignRequestSignatureException if invalid signature on certificate request.
     * @throws AuthStatusException if wrong status of user object.
     * @throws AuthLoginException if wrong credentials of user object.
     * @throws IllegalNameException if invalid request name for a certificate.
     * @throws CertificateCreateException if a serious error happens creating a certificate.
     * @throws CertificateRevokeException if an error revoking a certificate
     * @throws CertificateSerialNumberException if we create a certificate that already exists.
     * @throws IllegalValidityException if an invalid request validity period for a certificate.
     * @throws CAOfflineException if we use a CA that is offline
     * @throws InvalidAlgorithmException if an invalid request certificate signature algorithm for a certificate.
     * @throws SignatureException if generic Signature exception.
     * @throws CertificateException if a variety of certificate problems.
     * @throws AuthorizationDeniedException if not authorized
     * @throws CertificateExtensionException if advanced certificate extensions when it is configured with bad properties.
     * @throws CertificateRenewalException if an error occurs during Certificate Renewal.
     * @since RA Master API version 3 (EJBCA 6.12.0)
     */
    byte[] scepDispatch(AuthenticationToken authenticationToken, String operation, String message, String scepConfigurationAlias) throws CertificateEncodingException,
    NoSuchAliasException, CADoesntExistsException, NoSuchEndEntityException, CustomCertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException, SignRequestException,
    SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException,
    IllegalValidityException, CAOfflineException, InvalidAlgorithmException, SignatureException, CertificateException, AuthorizationDeniedException,
    CertificateExtensionException, CertificateRenewalException;

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

    /**
     * Dispatch EST request over RaMasterApi.
     *
     * Basic ASN.1 validation is performed at a proxy to increase the protection of a CA slightly.
     *
     * @param operation the EST operation to perform
     * @param alias the requested CA configuration that should handle the request.
     * @param cert The client certificate used to request this operation if any
     * @param username The authentication username if any
     * @param password The authentication password if any
     * @param requestBody The HTTP request body. Usually a PKCS#10
     * @return the HTTP response body
     *
     * @throws NoSuchAliasException if the alias doesn't exist
     * @throws CADoesntExistsException if the CA specified in a request for CA certs doesn't exist
     * @throws CertificateCreateException if an error was encountered when trying to enroll
     * @throws CertificateRenewalException if an error was encountered when trying to re-enroll
     * @throws AuthenticationFailedException if request was sent in without an authenticating certificate, or the username/password combo was
     *           invalid (depending on authentication method).
     *
     * @see org.ejbca.core.protocol.est.EstOperationsSessionRemote
     * @since RA Master API version 2 (EJBCA 6.11.0)
     */
    byte[] estDispatch(String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException;

    /**
     * Retrieves information about users
     *
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile of matching users&gt;/view_end_entity
     * - /ca/&lt;ca of usermatch&gt; - when matching on CA
     * </pre>
     *
     * @param authenticationToken the administrator performing the action
     * @param usermatch the unique user pattern to search for
     * @return a list of {@link org.ejbca.core.protocol.ws.client.gen.UserDataVOWS} objects (Max 100) containing the information about the user or null if there are no matches.
     * @throws AuthorizationDeniedException if client is not authorized to request.
     * @throws IllegalQueryException if query isn't valid
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws EndEntityProfileNotFoundException if EEP not found
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    List<UserDataVOWS> findUserWS(AuthenticationToken authenticationToken, UserMatch usermatch, int maxNumberOfRows)
            throws AuthorizationDeniedException, IllegalQueryException, EjbcaException, EndEntityProfileNotFoundException;

    /**
     * Returns the length of a publisher queue (aggregated over all separate instances, if found).
     *
     * @param name the name of the queue.
     * @return the length or -4 if the publisher does not exist
     * @throws AuthorizationDeniedException if client is not authorized to request.
     * @throws PublisherDoesntExistsException if no publisher exists with the given name.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    int getPublisherQueueLength(AuthenticationToken authenticationToken, String name) throws AuthorizationDeniedException, PublisherDoesntExistsException;

    /**
     * Retrieves the certificate chain for the signer. The returned certificate chain MUST have the
     * RootCA certificate in the last position.
     * @param authenticationToken the administrator performing the action
     * @param caId  is the issuer DN hashCode
     * @return Collection of Certificate, the certificate chain, never null.
     * @throws AuthorizationDeniedException if client isn't authorized to request
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getCertificateChain(final AuthenticationToken authenticationToken, int caId) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Retrieved the CA's public key as an SSH Public Key
     *
     * @param caName the name of the CA
     * @return the CA's public key encoded in SSH format
     * @throws SshKeyException if the CA is not an SSH CA
     * @throws CADoesntExistsException if the CA doesn't exist
     */
    byte[] getSshCaPublicKey(final String caName) throws SshKeyException, CADoesntExistsException;

    /**
     * Finds count of certificates  expiring within a specified time and that have
     * status "active" or "notifiedaboutexpiration".
     * @param days the number of days before the certificates will expire
     * @return return count of query results.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    int getCountOfCertificatesByExpirationTime(final AuthenticationToken authenticationToken, long days) throws AuthorizationDeniedException;

    /**
     * Writes a custom audit log into the database.
     *
     * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSession#customLog
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    void customLog(AuthenticationToken authenticationToken, String type, String caName, String username, String certificateSn, String msg, EventType event)
                throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Retrieves a collection of certificates as byte array generated for a user.
     *
     * @see org.ejbca.core.ejb.ra.EndEntityAccessSession#findCertificatesByUsername(AuthenticationToken, String, boolean, long)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getCertificatesByUsername(AuthenticationToken authenticationToken, String username, boolean onlyValid, long now) throws AuthorizationDeniedException, CertificateEncodingException;

    /**
     * Fetches available certificate profiles in an end entity profile.
     *
     * @see org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal#getAvailableCertificateProfiles(AuthenticationToken, int)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Map<String,Integer> getAvailableCertificateProfiles(AuthenticationToken authenticationToken, int entityProfileId) throws AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /**
     * Fetches the IDs and names of available CAs in an end entity profile.
     *
     * @see org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession#getAvailableCasInProfile(AuthenticationToken admin, int entityProfileId)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Map<String,Integer> getAvailableCasInProfile(AuthenticationToken authenticationToken, int entityProfileId) throws AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /**
     * Fetches an issued certificate.
     *
     * @see org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal#getCertificate(AuthenticationToken, String, String)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    CertificateWrapper getCertificate(AuthenticationToken authenticationToken, String certSNinHex, String issuerDN) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;

    /**
     * Fetches a list of up to <code>maxNumberOfResults</code> certificates which expires within
     * the next <code>days</code> days, ignoring the first <code>offset</code> certificates.
     * <p>
     * <b>Note:</b> the whole certificate chain is returned.
     * <p>
     * Authorization requirements:<pre>
     * - /administrator
     * - /ra_functionality/view_end_entity
     * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
     * - /ca/&lt;ca of user&gt;
     * </pre>
     *
     * @param authenticationToken an authentication token used for access control
     * @param days the maximum number of days before the certificates expire
     * @param maxNumberOfResults the maximum number of returned certificates
     * @return a collection of certificate wrappers, never null
     * @throws AuthorizationDeniedException if the calling user is not authorized to fetch one of the certificates
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getCertificatesByExpirationTime(AuthenticationToken authenticationToken, long days, int maxNumberOfResults,
            int offset) throws AuthorizationDeniedException;


    /**
     * Fetches a list of certificates that will expire within the given number of days and of the given type.
     *
     * @param authenticationToken the administrator performing the action.
     * @param days Expire time in days.
     * @param certificateType The type of the certificates. Use 0=Unknown  1=EndEntity  2=SUBCA  8=ROOTCA  16=HardToken.
     * @param maxNumberOfResults the maximum number of returned certificates.
     * @return A collection of certificate wrappers, never null.
     * @throws AuthorizationDeniedException if the calling administrator isn't authorized to fetch one of the certificates (not used).
     * @throws EjbcaException if at least one of the certificates is unreadable
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getCertificatesByExpirationTimeAndType(AuthenticationToken authenticationToken, long days, int certificateType, int maxNumberOfResults) throws AuthorizationDeniedException, EjbcaException;

    /**
     * Fetches a list of certificates that will expire within the given number of days and issued by the given issuer.
     *
     * @param authenticationToken the administrator performing the action.
     * @param days Expire time in days.
     * @param issuerDN The issuerDN of the certificates.
     * @param maxNumberOfResults the maximum number of returned certificates.
     * @return A collection of certificate wrappers, never null.
     * @throws AuthorizationDeniedException if the calling administrator isn't authorized to fetch one of the certificates (not used).
     * @throws EjbcaException if at least one of the certificates is unreadable.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getCertificatesByExpirationTimeAndIssuer(AuthenticationToken authenticationToken, long days, String issuerDN, int maxNumberOfResults) throws AuthorizationDeniedException, EjbcaException;

    /**
     * Fetches the current certificate chain for a CA.
     *
     * @see org.cesecore.certificates.ca.CaSession#getCaChain(AuthenticationToken, String)
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    Collection<CertificateWrapper> getLastCaChain(AuthenticationToken authenticationToken, String caName) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Processes a certificate request for the user with the given name.
     *
     * @see org.ejbca.core.ejb.ca.sign.SignSession#createCertificateWS
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    byte[] processCertificateRequest(AuthenticationToken authenticationToken, String username, String password, String req, int reqType, String hardTokenSN, String responseType)
        throws AuthorizationDeniedException, EjbcaException, CesecoreException, CertificateExtensionException,
               InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException,
               IOException, ParseException, ConstructionException, NoSuchFieldException;

    /**
     * Fetches the latest CRL issued by the given CA. This method is used by the Web Service.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * @param authenticationToken the administrator performing the action.
     * @param caName the name in EJBCA of the CA that issued the desired CRL.
     * @param deltaCRL false to fetch a full CRL, true to fetch a deltaCRL (if issued).
     * @return the latest CRL issued for the CA as a DER encoded byte array.
     * @throws AuthorizationDeniedException if client isn't authorized to request.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    byte[] getLatestCrl(AuthenticationToken authenticationToken, String caName, boolean deltaCRL) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Fetches the latest CRL issued by the given CA. This method is used by the Web Service.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * @param authenticationToken the administrator performing the action.
     * @param request the name in EJBCA of the CA that issued the desired CRL.
     * @return the latest CRL issued for the CA as a DER encoded byte array.
     * @throws AuthorizationDeniedException if client isn't authorized to request.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @since RA Master API version 7 (EJBCA 7.1.0)
     */
    byte[] getLatestCrlByRequest(AuthenticationToken authenticationToken, RaCrlSearchRequest request) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Fetches the latest CRL by issuerDn. This method is used by the REST API.
     *
     * Authorization requirements:<pre>
     * - /ca/&lt;caid&gt;
     * </pre>
     *
     * @param authenticationToken the administrator performing the action.
     * @param issuerDn the subjectDn in EJBCA of the CA that issued the desired CRL.
     * @param deltaCRL false to fetch a full CRL, true to fetch a deltaCRL (if issued).
     * @return the latest CRL issued for the CA as a DER encoded byte array.
     * @throws AuthorizationDeniedException if client isn't authorized to request.
     * @throws EjbcaException any EjbcaException.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
    byte[] getLatestCrlByIssuerDn(AuthenticationToken authenticationToken, String issuerDn, boolean deltaCRL) throws AuthorizationDeniedException, EjbcaException, CADoesntExistsException;

    /**
    * Fetches the remaining number of approvals for the given approval request.
    *
    * @param authenticationToken the administrator performing the action.
    * @param requestId the ID of an approval request.
    * @return the remaining number of approvals for this request (with 0 meaning that the request has passed or -1 if the request has been denied) or null if the request was proxied to another instance and the request has failed.
    * @throws AuthorizationDeniedException if client isn't authorized to request.
    * @throws ApprovalException if a request of the given ID didn't exist.
    * @throws ApprovalRequestExpiredException if approval request was expired before having a definite status.
    * @since RA Master API version 4 (EJBCA 6.14.0)
    *
    */
   Integer getRemainingNumberOfApprovals(AuthenticationToken authenticationToken, int requestId) throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException;

   /**
    * Looks up if a requested action has been approved.
    *
    * Authorization requirements: a valid client certificate.
    *
    * @see org.ejbca.core.ejb.approval.ApprovalSession#isApproved(int)
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
   Integer isApproved(AuthenticationToken authenticationToken, int approvalId) throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException;

   /**
    * Checks if a user is authorized to a given resource.
    *
    * Authorization requirements: a valid client certificate.
    *
    * @see org.cesecore.authorization.AuthorizationSession#isAuthorized(AuthenticationToken, String...)
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
   boolean isAuthorized(AuthenticationToken authenticationToken, String... resource);

   /**
    * Republishes a selected certificate.
    *
    * Authorization requirements:<pre>
    * - /administrator
    * - /ra_functionality/view_end_entity
    * - /endentityprofilesrules/&lt;end entity profile&gt;/view_end_entity
    * - /ca/&lt;ca of user&gt;
    * </pre>
    *
    * @param authenticationToken the administrator performing the action.
    * @param serialNumberInHex of the certificate to republish
    * @param issuerDN of the certificate to republish
    * @throws AuthorizationDeniedException if the administrator isn't authorized to republish.
    * @throws CADoesntExistsException if a referenced CA does not exist.
    * @throws PublisherException if something went wrong during publication.
    * @throws EjbcaException any EjbcaException.
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
   void republishCertificate(AuthenticationToken authenticationToken, String serialNumberInHex, String issuerDN)
           throws AuthorizationDeniedException, CADoesntExistsException, PublisherException, EjbcaException;

   /**
    * Creates a server-generated keystore for an existing user.
    *
    * @see org.ejbca.core.ejb.ra.KeyStoreCreateSession#generateOrKeyRecoverTokenAsByteArray
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
   byte[] generateOrKeyRecoverToken(AuthenticationToken authenticationToken, String username, String password, String hardTokenSN, String keySpecification, String keyAlgorithm)
           throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException;

   /**
    * Fetches the end entity profile by ID in XML format.
    *
    * @param profileId the end entity profile ID.
    * @return the XML formatted end entity profile as byte array.
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
    byte[] getEndEntityProfileAsXml(AuthenticationToken authenticationToken, int profileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException;

    /**
     * Fetches the certificate profile by ID in XML format.
     *
     * @param profileId the certificate profile ID.
     * @return the XML formatted end certificate profile as byte array.
     * @since RA Master API version 4 (EJBCA 6.14.0)
     */
     byte[] getCertificateProfileAsXml(AuthenticationToken authenticationToken, int profileId)
             throws AuthorizationDeniedException, CertificateProfileDoesNotExistException;

   /**
    * Generates a CV certificate for a user.
    *
    * @see org.ejbca.core.ejb.ca.sign.SignSession#createCardVerifiableCertificateWS
    * @since RA Master API version 4 (EJBCA 6.14.0)
    */
   @SuppressWarnings("deprecation")
   Collection<CertificateWrapper> processCardVerifiableCertificateRequest(AuthenticationToken authenticationToken, String username, String password, String cvcReq)
           throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
           EjbcaException, WaitingForApprovalException, CertificateExpiredException, CesecoreException;

    /**
    * Retrieves a set of all CAA identities for a CA, based on the CAA validators enabled. An empty set
    * of CAA identities are returned if no CAA validators are enabled.
    * @throws CADoesntExistsException if there is no CA with the given id
    * @throws AuthorizationDeniedException if authorisation was denied to the CA with the given id
    * @since RA Master API version 4 (EJBCA 6.14.0)
    * @return a set of CAA identities, never null
    */
    HashSet<String> getCaaIdentities(AuthenticationToken authenticationToken, int caId) throws AuthorizationDeniedException, CADoesntExistsException;

    /**
     * Get AcmeAccount by accountId.
     * @param accountId account id
     * @return the sought AcmeAccount or null if not found
     */
    AcmeAccount getAcmeAccountById(String accountId);

    /**
     * Get AcmeAccount by publicKeyStorageId.
     * @param publicKeyStorageId related public key storage id
     * @return the sought AcmeAccount or null if not found
     */
    AcmeAccount getAcmeAccountByPublicKeyStorageId(final String publicKeyStorageId);

    /**
     * Create or update the AcmeAccount.
     * @param acmeAccount account to persist
     * @return the persisted version of the AcmeAccount.
     */
   String persistAcmeAccount(final AcmeAccount acmeAccount);

   /**
    * Get AcmeOrder by orderId.
    * @param orderId order id
    * @return the sought AcmeOrder or null if not found
    */
   AcmeOrder getAcmeOrderById(String orderId);

   /**
    * Get AcmeOrders by accountId.
    * @param accountId a related account id
    * @return the collection of sought AcmeOrders or null if not found
    */
   Set<AcmeOrder> getAcmeOrdersByAccountId(final String accountId);

   /**
    * Get AcmeOrders by fingerprint field.
    * @param fingerprint a related acme order's fingerprint field
    * @return the collection of sought AcmeOrders or empty Set if not found
    */
   Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(final String fingerprint);

   /**
    * Create or update the AcmeOrder.
    * @param acmeOrder an order to persist
    * @return id of the persisted AcmeOrder.
    */
  String persistAcmeOrder(final AcmeOrder acmeOrder);

  /**
   * Create or update the AcmeOrders.
   * @param acmeOrders a list of orders to persist
   * @return list of ids of the persisted AcmeOrders.
   */
 List<String> persistAcmeOrders(final List<AcmeOrder> acmeOrders);

  /**
   * remove the AcmeOrder.
   * @param orderId order Id to be removed
   */
  void removeAcmeOrder(String orderId);

  /**
   * remove the provided list of AcmeOrders.
   * @param orderIds  order ids to be removed
   */
  void removeAcmeOrders(List<String> orderIds);

    /**
     * Get AcmeAuthorization by authorizationId.
     * @param authorizationId  authorization Id
     * @return the sought AcmeAuthorization or null if not found
     */
  AcmeAuthorization getAcmeAuthorizationById (final String authorizationId);

    /**
     * Get AcmeAuthorizations by orderId.
     * @param orderId a related order Id
     * @return the list of sought AcmeAuthorizations or null if not found
     */
  List<AcmeAuthorization> getAcmeAuthorizationsByOrderId (final String orderId);

    /**
     * Get AcmeAuthorizations by accountId.
     * @param accountId a related account id
     * @return the list of sought AcmeAuthorizations or null if not found
     */
  List<AcmeAuthorization> getAcmeAuthorizationsByAccountId (final String accountId);

    /**
     * Create or update the AcmeAuthorization.
     * @param acmeAuthorization an authorization to persist
     * @return id of the persisted AcmeAuthorization.
     */
    String persistAcmeAuthorization(final AcmeAuthorization acmeAuthorization);

    /**
     * Create or update the AcmeAuthorizations.
     * @param acmeAuthorizations a list of authorizations to persist
     */
    void persistAcmeAuthorizationList(final List<AcmeAuthorization> acmeAuthorizations);


    /**
     * Get AcmeChallenge by challengeId.
     * @param challengeId a challenge id
     * @return the sought AcmeChallenge or null if not found
     */
    AcmeChallenge getAcmeChallengeById (final String challengeId);

    /**
     * Get AcmeChallenges by authorizationId.
     * @param authorizationId an id of related authorization
     * @return the sought AcmeChallenge list or null if not found
     */
    List<AcmeChallenge> getAcmeChallengesByAuthorizationId(String authorizationId);

    /**
     * Create or update the AcmeChallenge.
     * @param acmeChallenge a challenge to persist
     * @return id of the persisted AcmeChallenge.
     */
    String persistAcmeChallenge(final AcmeChallenge acmeChallenge);

    /**
     * Create or update the AcmeChallenges.
     * @param acmeChallenges challenges list to persist
     */
    void persistAcmeChallengeList(final List<AcmeChallenge> acmeChallenges);

    /**
     * Gets the global configuration for the concrete type <T extends ConfigurationBase>.
     *
     * @see GlobalConfiguration
     * @see GlobalCesecoreConfiguration
     * @see GlobalAcmeConfiguration
     * @see GlobalOcspConfiguration
     * @see GlobalUpgradeConfiguration
     *
     * @param type the concrete global configuration object class.
     * @return the global configuration or null.
     */
    <T extends ConfigurationBase> T getGlobalConfiguration(Class<T> type);


}
