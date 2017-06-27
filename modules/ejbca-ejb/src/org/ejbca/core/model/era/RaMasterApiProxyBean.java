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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.DependsOn;
import javax.ejb.EJB;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.util.CertTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
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
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

/**
 * Proxy implementation of the the RaMasterApi that will will get the result of the most preferred API implementation
 * or a mix thereof depending of the type of call.
 * 
 * @version $Id$
 */
@Singleton
@Startup
@DependsOn("StartupSingletonBean")
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
@Lock(LockType.READ)
public class RaMasterApiProxyBean implements RaMasterApiProxyBeanLocal {

    private static final Logger log = Logger.getLogger(RaMasterApiProxyBean.class);

    @EJB
    private RaMasterApiSessionLocal raMasterApiSession;
    
    /** Note: Configuration stored <b>locally</b> on this peer. Should only be used for peer configuration, etc. */
    @EJB
    private GlobalConfigurationSessionLocal localNodeGlobalConfigurationSession;
    /** Used to store key recovery data <b>locally</b> on this peer. Should only be used for this purpose. */
    @EJB
    private KeyRecoverySessionLocal localNodeKeyRecoverySession;

    private RaMasterApi[] raMasterApis = null;
    private RaMasterApi[] raMasterApisLocalFirst = null;

    /** Default constructor */
    public RaMasterApiProxyBean() {
    }

    /** Constructor for use from JUnit tests */
    public RaMasterApiProxyBean(final RaMasterApi... raMasterApis) {
        this.raMasterApis = raMasterApis;
        final List<RaMasterApi> implementations = new ArrayList<>(Arrays.asList(raMasterApis));
        Collections.reverse(implementations);
        this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
    }

    @PostConstruct
    private void postConstruct() {
        final List<RaMasterApi> implementations = new ArrayList<>();
        try {
            // Load downstream peer implementation if available in this version of EJBCA
            final Class<?> c = Class.forName("org.ejbca.peerconnector.ra.RaMasterApiPeerDownstreamImpl");
            implementations.add((RaMasterApi) c.newInstance());
        } catch (ClassNotFoundException e) {
            log.debug("RaMasterApi over Peers is not available on this system.");
        } catch (InstantiationException | IllegalAccessException e) {
            log.warn("Failed to instantiate RaMasterApi over Peers: " + e.getMessage());
        }
        try {
            // Load upstream peer implementation if available in this version of EJBCA
            final Class<?> c = Class.forName("org.ejbca.peerconnector.ra.RaMasterApiPeerUpstreamImpl");
            implementations.add((RaMasterApi) c.newInstance());
        } catch (ClassNotFoundException e) {
            log.debug("RaMasterApi over Peers is not available on this system.");
        } catch (InstantiationException | IllegalAccessException e) {
            log.warn("Failed to instantiate RaMasterApi over Peers: " + e.getMessage());
        }
        implementations.add(raMasterApiSession);
        this.raMasterApis = implementations.toArray(new RaMasterApi[implementations.size()]);
        Collections.reverse(implementations);
        this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
    }

    @Override
    public boolean isBackendAvailable() {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isBackendAvailable(Class<? extends RaMasterApi> apiType) {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()  && apiType.isInstance(raMasterApi) ) {
                return true;
            }
        }
        return false;
    }
    
    // Added in Master RA API version 1
    @Override
    public int getApiVersion() {
        int minApiVersion = Integer.MAX_VALUE;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    minApiVersion = Math.min(minApiVersion, raMasterApi.getApiVersion());
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return minApiVersion == Integer.MAX_VALUE ? 0 : minApiVersion;
    }

    @Override
    public boolean isAuthorizedNoLogging(final AuthenticationToken authenticationToken, final String... resources) {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    if (raMasterApi.isAuthorizedNoLogging(authenticationToken, resources)) {
                        return true;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return false;
    }

    @Override
    public RaAuthorizationResult getAuthorization(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        RaAuthorizationResult combinedResult = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final RaAuthorizationResult raAuthorizationResult = raMasterApi.getAuthorization(authenticationToken);
                    if (combinedResult==null) {
                        combinedResult = raAuthorizationResult;
                    } else {
                        final HashMap<String, Boolean> accessRules = AccessRulesHelper.getAccessRulesUnion(combinedResult.getAccessRules(),
                                raAuthorizationResult.getAccessRules());
                        // Sum of update numbers is strictly growing under the assumption that all backends are still connected
                        final int combinedUpdateNumber = combinedResult.getUpdateNumber() + raAuthorizationResult.getUpdateNumber();
                        combinedResult = new RaAuthorizationResult(accessRules, combinedUpdateNumber);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (combinedResult==null) {
            combinedResult = new RaAuthorizationResult(null, 0);
        }
        return combinedResult;
    }

    @Override
    @Deprecated
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        AccessSet merged = new AccessSet(new HashSet<String>());
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    AccessSet as = raMasterApi.getUserAccessSet(authenticationToken);
                    merged = new AccessSet(merged, as);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return merged;
    }

    @Override
    @Deprecated
    public List<AccessSet> getUserAccessSets(final List<AuthenticationToken> authenticationTokens) {
        final List<AuthenticationToken> tokens = new ArrayList<>(authenticationTokens);
        final AccessSet[] merged = new AccessSet[authenticationTokens.size()];
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final List<AccessSet> accessSets = raMasterApi.getUserAccessSets(tokens);
                    for (int i = 0; i < accessSets.size(); i++) {
                        if (merged[i] == null) {
                            merged[i] = accessSets.get(i);
                        } else {
                            merged[i] = new AccessSet(accessSets.get(i), merged[i]);
                        }
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return Arrays.asList(merged);
    }

    @Override
    public List<CAInfo> getAuthorizedCas(final AuthenticationToken authenticationToken) {
        final Map<Integer, CAInfo> caInfoMap = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    for (final CAInfo caInfo : raMasterApi.getAuthorizedCas(authenticationToken)) {
                        caInfoMap.put(caInfo.getCAId(), caInfo);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return new ArrayList<>(caInfoMap.values());
    }
    
    @Override
    public List<Role> getAuthorizedRoles(final AuthenticationToken authenticationToken) {
        final Map<Integer, Role> roleMap = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    for (final Role role : raMasterApi.getAuthorizedRoles(authenticationToken)) {
                        roleMap.put(role.getRoleId(), role);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return new ArrayList<>(roleMap.values());
    }
    
    @Override
    public Role getRole(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    Role role = raMasterApi.getRole(authenticationToken, roleId);
                    if (role != null) {
                        return role;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<String> getAuthorizedRoleNamespaces(final AuthenticationToken authenticationToken, final int roleId) {
        final Set<String> namespaceSet = new HashSet<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    namespaceSet.addAll(raMasterApi.getAuthorizedRoleNamespaces(authenticationToken, roleId));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return new ArrayList<>(namespaceSet);
    }
    
    @Override
    public Map<String,RaRoleMemberTokenTypeInfo> getAvailableRoleMemberTokenTypes(final AuthenticationToken authenticationToken) {
        final HashMap<String,RaRoleMemberTokenTypeInfo> result = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final Map<String,RaRoleMemberTokenTypeInfo> mergeWith = raMasterApi.getAvailableRoleMemberTokenTypes(authenticationToken);
                    for (final Map.Entry<String,RaRoleMemberTokenTypeInfo> entry : mergeWith.entrySet()) {
                        final String tokenType = entry.getKey();
                        final RaRoleMemberTokenTypeInfo entryInfo = entry.getValue();
                        final RaRoleMemberTokenTypeInfo resultInfo = result.get(tokenType);
                        if (resultInfo == null) {
                            result.put(tokenType, entryInfo);
                        } else {
                            resultInfo.merge(entryInfo);
                        }
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return result;
    }
    
    @Override
    public Role saveRole(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException, RoleExistsException {
        AuthorizationDeniedException authorizationDeniedException = null;
        // Try to save/update on the systems until successful, starting with the remote systems first.
        // (The save operation might be unsuccessful if we're editing an existing role that belongs to another system, for instance)
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    final Role savedRole = raMasterApi.saveRole(authenticationToken, role);
                    if (savedRole != null) {
                        return savedRole;
                    }
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return null;
    }
    
    @Override
    public boolean deleteRole(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException {
        AuthorizationDeniedException authorizationDeniedException = null;
        boolean result = false;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    result |= raMasterApi.deleteRole(authenticationToken, roleId);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (!result && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return result;
    }
    
    @Override
    public RoleMember getRoleMember(AuthenticationToken authenticationToken, int roleMemberId) throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    RoleMember roleMember = raMasterApi.getRoleMember(authenticationToken, roleMemberId);
                    if (roleMember != null) {
                        return roleMember;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public RoleMember saveRoleMember(AuthenticationToken authenticationToken, RoleMember roleMember) throws AuthorizationDeniedException {
        AuthorizationDeniedException authorizationDeniedException = null;
        // Try to save/update on the systems until successful, starting with the remote systems first.
        // (The save operation might be unsuccessful if we're editing an existing role member that belongs to another system,
        // or if we're trying to add a role member and the role it references to belongs to another system)
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    final RoleMember savedRoleMember = raMasterApi.saveRoleMember(authenticationToken, roleMember);
                    if (savedRoleMember != null) {
                        return savedRoleMember;
                    }
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return null;
    }
    
    @Override
    public boolean deleteRoleMember(AuthenticationToken authenticationToken, int roleId, int roleMemberId) throws AuthorizationDeniedException {
        AuthorizationDeniedException authorizationDeniedException = null;
        boolean result = false;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    result |= raMasterApi.deleteRoleMember(authenticationToken, roleId, roleMemberId);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (!result && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return result;
    }

    @Override
    public RaApprovalRequestInfo getApprovalRequest(AuthenticationToken authenticationToken, int id) {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    RaApprovalRequestInfo reqInfo = raMasterApi.getApprovalRequest(authenticationToken, id);
                    if (reqInfo != null) {
                        return reqInfo;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public RaApprovalRequestInfo getApprovalRequestByRequestHash(AuthenticationToken authenticationToken, int approvalId) {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    RaApprovalRequestInfo reqInfo = raMasterApi.getApprovalRequestByRequestHash(authenticationToken, approvalId);
                    if (reqInfo != null) {
                        return reqInfo;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public RaApprovalRequestInfo editApprovalRequest(AuthenticationToken authenticationToken, RaApprovalEditRequest edit)
            throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final RaApprovalRequestInfo newApproval = raMasterApi.editApprovalRequest(authenticationToken, edit);
                    if (newApproval != null) {
                        return newApproval;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }
    
    @Override
    public void extendApprovalRequest(AuthenticationToken authenticationToken, int id, long extendForMillis) throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    raMasterApi.extendApprovalRequest(authenticationToken, id, extendForMillis);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }

    @Override
    public boolean addRequestResponse(AuthenticationToken authenticationToken, RaApprovalResponseRequest requestResponse)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException, ApprovalRequestExecutionException,
            AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    if (raMasterApi.addRequestResponse(authenticationToken, requestResponse)) {
                        return true;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return false;
    }

    @Override
    public RaRequestsSearchResponse searchForApprovalRequests(AuthenticationToken authenticationToken,
            RaRequestsSearchRequest raRequestsSearchRequest) {
        final RaRequestsSearchResponse searchResponse = new RaRequestsSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    searchResponse.merge(raMasterApi.searchForApprovalRequests(authenticationToken, raRequestsSearchRequest));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return searchResponse;
    }

    @Override
    public CertificateDataWrapper searchForCertificate(final AuthenticationToken authenticationToken, final String fingerprint) {
        CertificateDataWrapper searchResponse = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    searchResponse = raMasterApi.searchForCertificate(authenticationToken, fingerprint);
                    if (searchResponse != null) {
                        break;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return searchResponse;
    }

    @Override
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken,
            RaCertificateSearchRequest raCertificateSearchRequest) {
        final RaCertificateSearchResponse ret = new RaCertificateSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForCertificates(authenticationToken, raCertificateSearchRequest));
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Trouble during back end invocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end invocation.", e);
                    }
                    // If the back end timed out due to a too heavy search we want to allow the client to retry with more fine grained criteria
                    ret.setMightHaveMoreResults(true);
                }
            }
        }
        return ret;
    }
    
    @Override
    public RaRoleSearchResponse searchForRoles(AuthenticationToken authenticationToken,
            RaRoleSearchRequest raRoleSearchRequest) {
        final RaRoleSearchResponse ret = new RaRoleSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForRoles(authenticationToken, raRoleSearchRequest));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }
    
    @Override
    public RaRoleMemberSearchResponse searchForRoleMembers(AuthenticationToken authenticationToken,
            RaRoleMemberSearchRequest raRoleMemberSearchRequest) {
        final RaRoleMemberSearchResponse ret = new RaRoleMemberSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForRoleMembers(authenticationToken, raRoleMemberSearchRequest));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken,
            RaEndEntitySearchRequest raEndEntitySearchRequest) {
        final RaEndEntitySearchResponse ret = new RaEndEntitySearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForEndEntities(authenticationToken, raEndEntitySearchRequest));
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Trouble during back end invocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end invocation.", e);
                    }
                    // If the back end timed out due to a too heavy search we want to allow the client to retry with more fine grained criteria
                    ret.setMightHaveMoreResults(true);
                }
            }
        }
        return ret;
    }

    @Override
    public Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(final AuthenticationToken authenticationToken) {
        final Map<Integer, String> ret = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.putAll(raMasterApi.getAuthorizedCertificateProfileIdsToNameMap(authenticationToken));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(final AuthenticationToken authenticationToken) {
        final Map<Integer, String> ret = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.putAll(raMasterApi.getAuthorizedEndEntityProfileIdsToNameMap(authenticationToken));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final String endEntityAccessRule) {
        final IdNameHashMap<EndEntityProfile> ret = new IdNameHashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final IdNameHashMap<EndEntityProfile> result = raMasterApi.getAuthorizedEndEntityProfiles(authenticationToken, endEntityAccessRule);
                    if (result != null) {
                        ret.putAll(result);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken) {
        final IdNameHashMap<CAInfo> ret = new IdNameHashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final IdNameHashMap<CAInfo> result = raMasterApi.getAuthorizedCAInfos(authenticationToken);
                    if (result != null) {
                        ret.putAll(result);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken) {
        final IdNameHashMap<CertificateProfile> ret = new IdNameHashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final IdNameHashMap<CertificateProfile> result = raMasterApi.getAuthorizedCertificateProfiles(authenticationToken);
                    if (result != null) {
                        ret.putAll(result);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public CertificateProfile getCertificateProfile(int id) {
        CertificateProfile ret = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret = raMasterApi.getCertificateProfile(id);
                    if (ret != null) {
                        // If we did get a hit, we don't need to cycle through other implementations
                        break;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public boolean addUser(AuthenticationToken admin, EndEntityInformation endEntity, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    return raMasterApi.addUser(admin, endEntity, clearpwd);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return false;
    }
    
    @Override
    public void checkSubjectDn(AuthenticationToken admin, EndEntityInformation endEntity) throws AuthorizationDeniedException, EjbcaException{
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    raMasterApi.checkSubjectDn(admin, endEntity);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
    }

    @Override
    public void deleteUser(final AuthenticationToken authenticationToken, final String username) throws AuthorizationDeniedException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable()) {
                    raMasterApi.deleteUser(authenticationToken, username);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
    }

    @Override
    public EndEntityInformation searchUser(AuthenticationToken authenticationToken, String username) {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final EndEntityInformation result = raMasterApi.searchUser(authenticationToken, username);
                    if (result != null) {
                        return result;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public void checkUserStatus(AuthenticationToken authenticationToken, String username, String password)
            throws NoSuchEndEntityException, AuthStatusException, AuthLoginException {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    raMasterApi.checkUserStatus(authenticationToken, username, password);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }

    // This method is somewhat special, because it should not be sent/forwarded upstream depending on a configuration setting
    @Override
    public byte[] generateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        EjbcaException userNotFoundException = null;
        RaMasterApi[] apiOrdered = raMasterApis;
        
        GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (endEntity.getKeyRecoverable() && globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery()) {
            // "Force local key recovery" enabled. The certificate is issued on the CA, but the key pair is generated and stored locally.
            EndEntityInformation storedEndEntity = searchUser(authenticationToken, endEntity.getUsername());
            if (storedEndEntity.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY) {
                try {
                    final IdNameHashMap<CAInfo> caInfos = getAuthorizedCAInfos(authenticationToken);
                    final CAInfo caInfo = caInfos.getValue(endEntity.getCAId());
                    if (caInfo == null) {
                        throw new AuthorizationDeniedException("Not authorized to CA with ID " + endEntity.getCAId() + ", or it does not exist.");
                    }
                    Certificate[] cachain = caInfo.getCertificateChain().toArray(new Certificate[0]);
                    // Create new key pair and CSR
                    final String keyalg = endEntity.getExtendedinformation().getKeyStoreAlgorithmType();
                    final String keyspec = endEntity.getExtendedinformation().getKeyStoreAlgorithmSubType();
                    final KeyPair kp = KeyTools.genKeys(keyspec, keyalg);
                    final X500Name x509dn = CertTools.stringToBcX500Name(endEntity.getDN());
                    final String sigAlg = AlgorithmTools.getSignatureAlgorithms(kp.getPublic()).get(0);
                    final PKCS10CertificationRequest pkcs10req = CertTools.genPKCS10CertificationRequest(sigAlg, x509dn, kp.getPublic(), null, kp.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
                    final byte[] csr = pkcs10req.getEncoded();
                    endEntity.getExtendedinformation().setCertificateRequest(csr); // not persisted, only sent over peer connection
                    // Request certificate
                    final byte[] certBytes = createCertificate(authenticationToken, endEntity);
                    final X509Certificate cert = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
                    // Store key pair
                    final Integer cryptoTokenId = globalConfig.getLocalKeyRecoveryCryptoTokenId();
                    final String keyAlias = globalConfig.getLocalKeyRecoveryKeyAlias();
                    if (cryptoTokenId == null || keyAlias == null) {
                        log.warn("No key has been configured for local key recovery. Please select a crypto token and key alias in System Configuration!");
                        throw new EjbcaException(ErrorCode.INTERNAL_ERROR);
                    }
                    if (localNodeKeyRecoverySession.addKeyRecoveryData(authenticationToken, cert, endEntity.getUsername(), kp, cryptoTokenId, keyAlias)) {
                        throw new EjbcaException(ErrorCode.INTERNAL_ERROR);
                    }
                    // Build keystore
                    final KeyStore ks;
                    String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
                    if (alias == null) {
                        alias = endEntity.getUsername();
                    }
                    if (endEntity.getTokenType() == EndEntityConstants.TOKEN_SOFT_JKS) {
                        ks = KeyTools.createJKS(alias, kp.getPrivate(), endEntity.getPassword(), cert, cachain);
                    } else {
                        ks = KeyTools.createP12(alias, kp.getPrivate(), cert, cachain);
                    }
                    try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                        ks.store(baos, endEntity.getPassword().toCharArray());
                        return baos.toByteArray();
                    }
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException |
                        InvalidAlgorithmParameterException | OperatorCreationException | IOException e) {
                    throw new IllegalStateException(e);
                }
            } else {
                // Recover existing key pair
                apiOrdered = raMasterApisLocalFirst;
            }
        }
        
        for (final RaMasterApi raMasterApi : apiOrdered) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.generateKeyStore(authenticationToken, endEntity);
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (EjbcaException e) {
                    // If the user is not found (e.g. during key recovery), try next implementation
                    if (!ErrorCode.USER_NOT_FOUND.equals(e.getErrorCode())) {
                        throw e;
                    }
                    if (userNotFoundException != null) {
                        userNotFoundException = e;
                    }
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (userNotFoundException != null) {
            throw userNotFoundException;
        }
        return null;
    }

    @Override
    public byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.createCertificate(authenticationToken, endEntity);
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return null;
    }
    
    @Override
    public byte[] createCertificateWS(final AuthenticationToken authenticationToken, final UserDataVOWS userdata, final String requestData, final int requestType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, ApprovalException, EjbcaException,
            EndEntityProfileValidationException {
        AuthorizationDeniedException authorizationDeniedException = null;
        EjbcaException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.createCertificateWS(authenticationToken, userdata, requestData, requestType, hardTokenSN, responseType);
                } catch (EjbcaException e) {
                    // Only catch "CA doesn't exist" case here
                    if (e.getErrorCode() != null && !ErrorCode.CA_NOT_EXISTS.getInternalErrorCode().equals(e.getErrorCode().getInternalErrorCode())) {
                        throw e;
                    }
                    if (caDoesntExistException == null) {
                        caDoesntExistException = e;
                    }
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
        return null;
    }
    
    @Override
    public List<CertificateWrapper> getLastCertChain(final AuthenticationToken authenticationToken, final String username) throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                     final List<CertificateWrapper> chain = raMasterApi.getLastCertChain(authenticationToken, username);
                     if (!chain.isEmpty()) {
                         return chain;
                     }
                     // Otherwise, try next implementation
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return new ArrayList<>();
    }

    @Override
    public boolean changeCertificateStatus(final AuthenticationToken authenticationToken, final String fingerprint, final int newStatus,
            final int newRevocationReason) throws ApprovalException, WaitingForApprovalException {
        boolean ret = false;
        // Try remote first, since the certificate might be present in the RA database but the admin might not authorized to revoke it there
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret = raMasterApi.changeCertificateStatus(authenticationToken, fingerprint, newStatus, newRevocationReason);
                    if (ret) {
                        break;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }
    


    @Override
    public ApprovalProfile getApprovalProfileForAction(final AuthenticationToken authenticationToken, final ApprovalRequestType action, final int caId, final int certificateProfileId) throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final ApprovalProfile result = raMasterApi.getApprovalProfileForAction(authenticationToken, action, caId, certificateProfileId);
                    if (result != null) {
                        return result;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public byte[] cmpDispatch(final AuthenticationToken authenticationToken, final byte[] pkiMessageBytes, final String cmpConfigurationAlias) throws NoSuchAliasException {
        NoSuchAliasException caughtException = null;
        
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion()>=1) {
                try {
                    byte[] result;
                    try {
                        result = raMasterApi.cmpDispatch(authenticationToken, pkiMessageBytes, cmpConfigurationAlias);
                        return result;
                    } catch (NoSuchAliasException e) {
                        //We might not have an alias in the current RaMasterApi, so let's try another. Let's store the exception in case we need it
                        //later though.
                        caughtException = e;
                    }                    
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        // either throw an exception or return null
        if (caughtException != null) {
            throw caughtException;
        } else {
            return null;
        }
    }
}
