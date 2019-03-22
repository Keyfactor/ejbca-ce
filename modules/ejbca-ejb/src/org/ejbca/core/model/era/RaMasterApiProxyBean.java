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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

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

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.NotFoundException;
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
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;
import org.ejbca.util.query.IllegalQueryException;

/**
 * Proxy implementation of the the RaMasterApi that will get the result of the most preferred API implementation
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

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;

    private RaMasterApi[] raMasterApis = null;
    private RaMasterApi[] raMasterApisLocalFirst = null;

    /** Default constructor */
    public RaMasterApiProxyBean() {
    }

    /** Constructor for use from JUnit tests */
    public RaMasterApiProxyBean(final RaMasterApiSessionLocal raMasterApiSession,
            final GlobalConfigurationSessionLocal globalConfigurationSession,
            final KeyRecoverySessionLocal keyRecoverySession,
            final RaMasterApi... raMasterApis) {
        this.raMasterApis = raMasterApis;
        final List<RaMasterApi> implementations = new ArrayList<>(Arrays.asList(raMasterApis));
        Collections.reverse(implementations);
        this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
        this.raMasterApiSession = raMasterApiSession;
        this.localNodeGlobalConfigurationSession = globalConfigurationSession;
        this.localNodeKeyRecoverySession = keyRecoverySession;
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

    // Use in tests only!
    @Override
    public void deferLocalForTest() {
        raMasterApisLocalFirst = (RaMasterApi[]) ArrayUtils.removeElement(raMasterApisLocalFirst, raMasterApiSession);
        raMasterApisLocalFirst = (RaMasterApi[]) ArrayUtils.add(raMasterApisLocalFirst, raMasterApiSession);
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
    public LinkedHashMap<Integer, RaStyleInfo> getAllCustomRaStyles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        for (RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) { // added between v1 and v2, lacks an exact version
                try {
                    LinkedHashMap<Integer, RaStyleInfo> raCssInfos = raMasterApi.getAllCustomRaStyles(authenticationToken);
                    if (!raCssInfos.isEmpty()) {
                        return raCssInfos;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<RaStyleInfo> getAvailableCustomRaStyles(AuthenticationToken authenticationToken, int hashCodeOfCurrentList) {
        for (RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) { // added between v1 and v2, lacks an exact version
                try {
                    final List<RaStyleInfo>raStyleInfos = raMasterApi.getAvailableCustomRaStyles(authenticationToken, hashCodeOfCurrentList);
                    if (raStyleInfos == null || !raStyleInfos.isEmpty()) { // null means that it is unchanged
                        return raStyleInfos;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return new ArrayList<>();
    }

    @Override
    public List<Role> getAuthorizedRoles(final AuthenticationToken authenticationToken) {
        final Map<Integer, Role> roleMap = new HashMap<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            try {
                if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            try {
                if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            try {
                if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            try {
                if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
    public CertificateDataWrapper searchForCertificateByIssuerAndSerial(final AuthenticationToken authenticationToken, final String issuerDN, final String serno) {
        CertificateDataWrapper searchResponse = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    searchResponse = raMasterApi.searchForCertificateByIssuerAndSerial(authenticationToken, issuerDN, serno);
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
    public RaCertificateSearchResponse searchForCertificatesByUsername(
            final AuthenticationToken authenticationToken, final String username) {
        RaCertificateSearchRequest request = new RaCertificateSearchRequest();
        request.setUsernameSearchString(username);
        request.setUsernameSearchExact(true);
        return searchForCertificates(authenticationToken, request);
    }

    @Override
    public RaRoleSearchResponse searchForRoles(AuthenticationToken authenticationToken,
            RaRoleSearchRequest raRoleSearchRequest) {
        final RaRoleSearchResponse ret = new RaRoleSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
    public boolean addUserFromWS(final AuthenticationToken admin, UserDataVOWS userDataVOWS, final boolean clearpwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        CADoesntExistsException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            try {
                if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                    return raMasterApi.addUserFromWS(admin, userDataVOWS, clearpwd);
                }
            } catch (AuthorizationDeniedException e) {
                if (authorizationDeniedException == null) {
                    authorizationDeniedException = e;
                }
                // Just try next implementation
            } catch (CADoesntExistsException e) {
                if (caDoesntExistException == null) {
                    caDoesntExistException = e;
                }
                // Just try next implementation
            } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                // Just try next implementation
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
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
        NoSuchEndEntityException noSuchEndEntityException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
                try {
                    raMasterApi.checkUserStatus(authenticationToken, username, password);
                    return;
                } catch (NoSuchEndEntityException e) {
                    if (noSuchEndEntityException != null) {
                        noSuchEndEntityException = e;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (noSuchEndEntityException != null) {
            throw noSuchEndEntityException;
        }
    }

    @Override
    public void finishUserAfterLocalKeyRecovery(final AuthenticationToken authenticationToken, final String username, final String password) throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        EjbcaException userNotFoundException = null;

        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) { // added between v1 and v2, lacks an exact version
                try {
                    raMasterApi.finishUserAfterLocalKeyRecovery(authenticationToken, username, password);
                    return;
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
    }

    private X509Certificate requestCertForEndEntity(final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final String password, final KeyPair kp)
            throws AuthorizationDeniedException, EjbcaException {
        try {
            final X500Name x509dn = CertTools.stringToBcX500Name(endEntity.getDN());
            final String sigAlg = AlgorithmTools.getSignatureAlgorithms(kp.getPublic()).get(0);
            final PKCS10CertificationRequest pkcs10req = CertTools.genPKCS10CertificationRequest(sigAlg, x509dn, kp.getPublic(), null, kp.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
            final byte[] csr = pkcs10req.getEncoded();
            endEntity.getExtendedInformation().setCertificateRequest(csr); // not persisted, only sent over peer connection
            endEntity.setPassword(password); // not persisted
            // Request certificate
            final byte[] certBytes = createCertificate(authenticationToken, endEntity);
            return CertTools.getCertfromByteArray(certBytes, X509Certificate.class);
        } catch (IOException | OperatorCreationException | CertificateParsingException e) {
            throw new IllegalStateException(e);
        }
    }

    // This method is somewhat special, because it should not be sent/forwarded upstream depending on a configuration setting
    @Override
    public byte[] generateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        EjbcaException userNotFoundException = null;

        final String username = endEntity.getUsername();
        final EndEntityInformation storedEndEntity = searchUser(authenticationToken, username);
        if (storedEndEntity == null) {
            throw new EjbcaException(ErrorCode.USER_NOT_FOUND, "User does not exist: " + username);
        }
        GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (storedEndEntity.getKeyRecoverable() && globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery()) {
            // "Force local key recovery" enabled. The certificate is issued on the CA, but the key pair is generated and stored locally.
            final IdNameHashMap<CAInfo> caInfos = getAuthorizedCAInfos(authenticationToken);
            final CAInfo caInfo = caInfos.getValue(storedEndEntity.getCAId());
            if (caInfo == null) {
                throw new AuthorizationDeniedException("Not authorized to CA with ID " + storedEndEntity.getCAId() + ", or it does not exist.");
            }
            final Certificate[] cachain = caInfo.getCertificateChain().toArray(new Certificate[0]);
            if (!isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY)) {
                throw new AuthorizationDeniedException("Not authorized to recover keys");
            }
            final EndEntityProfile endEntityProfile = getAuthorizedEndEntityProfiles(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY).getValue(storedEndEntity.getEndEntityProfileId());
            if (endEntityProfile == null) {
                throw new AuthorizationDeniedException("Not authorized to End Entity Profile with ID " + storedEndEntity.getEndEntityProfileId() + ", or it does not exist.");
            }

            final Integer cryptoTokenId = globalConfig.getLocalKeyRecoveryCryptoTokenId();
            final String keyAlias = globalConfig.getLocalKeyRecoveryKeyAlias();
            final X509Certificate cert;
            final KeyPair kp;
            try {
                if (storedEndEntity.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY) {
                    if (log.isDebugEnabled()) {
                        log.debug("Creating locally stored key pair for end entity '" + username + "'");
                    }
                    // Create new key pair and CSR
                    final String keyalg = storedEndEntity.getExtendedInformation().getKeyStoreAlgorithmType();
                    final String keyspec = storedEndEntity.getExtendedInformation().getKeyStoreAlgorithmSubType();
                    kp = KeyTools.genKeys(keyspec, keyalg);
                    // requestCertForEndEntity verifies the password and performs the finishUser operation
                    cert = requestCertForEndEntity(authenticationToken, storedEndEntity, endEntity.getPassword(), kp);
                    // Store key pair
                    if (cryptoTokenId == null || keyAlias == null) {
                        log.warn("No key has been configured for local key recovery. Please select a crypto token and key alias in System Configuration!");
                        throw new EjbcaException(ErrorCode.INTERNAL_ERROR);
                    }
                    if (!localNodeKeyRecoverySession.addKeyRecoveryDataInternal(authenticationToken, EJBTools.wrap(cert), username, EJBTools.wrap(kp), cryptoTokenId, keyAlias)) {
                        // Should never happen. An exception stack trace is error-logged in addKeyRecoveryData
                        throw new EjbcaException(ErrorCode.INTERNAL_ERROR);
                    }
                } else {
                    // Recover existing key pair
                    if (log.isDebugEnabled()) {
                        log.debug("Recovering locally stored key pair for end entity '" + username + "'");
                    }
                    final KeyRecoveryInformation kri = localNodeKeyRecoverySession.recoverKeysInternal(authenticationToken, username, cryptoTokenId, keyAlias);
                    if (kri == null) {
                        // This should not happen when the user has its status set to KEYRECOVERY
                        final String message = "Could not find key recovery data for end entity '" + username + "'";
                        log.debug(message);
                        throw new EjbcaException(ErrorCode.INTERNAL_ERROR, message);
                    }
                    kp = kri.getKeyPair();
                    if (endEntityProfile.getReUseKeyRecoveredCertificate()) {
                        final CertificateDataWrapper cdw = searchForCertificateByIssuerAndSerial(authenticationToken, kri.getIssuerDN(), kri.getCertificateSN().toString(16));
                        if (cdw == null) {
                            final String msg = "Key recovery data exists for user '" + username + "', but certificate does not: " + kri.getCertificateSN().toString(16);
                            log.info(msg);
                            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, msg);
                        }
                        cert = (X509Certificate) cdw.getCertificate();
                        // Verify password and finish user
                        finishUserAfterLocalKeyRecovery(authenticationToken, username, endEntity.getPassword());
                    } else {
                        // requestCertForEndEntity verifies the password and performs the finishUser operation
                        cert = requestCertForEndEntity(authenticationToken, storedEndEntity, endEntity.getPassword(), kp);
                    }
                    localNodeKeyRecoverySession.unmarkUser(authenticationToken, username);
                }
                // Build keystore
                final KeyStore ks;
                String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
                if (alias == null) {
                    alias = username;
                }
                if (storedEndEntity.getTokenType() == EndEntityConstants.TOKEN_SOFT_JKS) {
                    ks = KeyTools.createJKS(alias, kp.getPrivate(), endEntity.getPassword(), cert, cachain);
                } else {
                    ks = KeyTools.createP12(alias, kp.getPrivate(), cert, cachain);
                }
                try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    ks.store(baos, endEntity.getPassword().toCharArray());
                    return baos.toByteArray();
                }
            } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException |
                    InvalidAlgorithmParameterException | IOException e) {
                throw new IllegalStateException(e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Requesting key store for end entity '" + username + "'. Remote peer systems will be queried first");
            }
        }

        for (final RaMasterApi raMasterApi : raMasterApis) {
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
        EjbcaException ejbcaException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.createCertificate(authenticationToken, endEntity);
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (EjbcaException e) {
                    if (!(e.getCause() instanceof NoSuchEndEntityException)) {
                        throw e; // rethrow everything else
                    } else if (ejbcaException != null) {
                        ejbcaException = e;
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
        if (ejbcaException != null) {
            throw ejbcaException;
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
        	if (log.isDebugEnabled()) {
        	    log.debug("raMasterApi calling createCertificateWS: "+raMasterApi.getApiVersion()+", "+raMasterApi.isBackendAvailable()+", "+raMasterApi.getClass());
        	}
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
    public byte[] createCertificateRest(final AuthenticationToken authenticationToken, EnrollPkcs10CertificateRequest enrollcertificateRequest)
            throws CertificateProfileDoesNotExistException, CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileNotFoundException,
            EjbcaException, EndEntityProfileValidationException {
        CADoesntExistsException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                if (log.isDebugEnabled()) {
                    log.debug("raMasterApi calling createCertificateRest: "+raMasterApi.getApiVersion()+", "+raMasterApi.isBackendAvailable()+", "+raMasterApi.getClass());
                }
                try {
                    return raMasterApi.createCertificateRest(authenticationToken, enrollcertificateRequest);
                } catch (CADoesntExistsException e) {
                    caDoesntExistException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
        return null;
    }

    @Override
    public void keyRecoverWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN) throws EjbcaException, AuthorizationDeniedException,
                                WaitingForApprovalException, ApprovalException, CADoesntExistsException {
        // Handle local key recovery (Key recovery data is stored locally)
        GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery()) {
            if (searchUser(authenticationToken, username) == null) {
                throw new NotFoundException("User with username '" + username + "' was not found");
            }
            // Search for the certificate on all implementations
            CertificateDataWrapper cdw = searchForCertificateByIssuerAndSerial(authenticationToken, issuerDN, certSNinHex);
            if (cdw == null) {
                throw new NotFoundException("Certificate for user: '" + username + "' with serialNr: '" + certSNinHex + "' issued by: '" + issuerDN + "' was not found");
            }
            final boolean localRecoveryPossible = keyRecoveryPossible(authenticationToken, cdw.getCertificate(), username);
            if (!localRecoveryPossible) {
                throw new EjbcaException(ErrorCode.KEY_RECOVERY_NOT_AVAILABLE);
            }
            try {
                // Attempts recovery on all implementations
                markForRecovery(authenticationToken, username, null, cdw, true);
            } catch (NoSuchEndEntityException e) {
                // To not mess with the WS API
                throw new NotFoundException(e.getMessage());
            } catch (EndEntityProfileValidationException e) {
                // To not mess with the WS API
                throw new EjbcaException(ErrorCode.USER_DOESNT_FULFILL_END_ENTITY_PROFILE);
            }
            // We are done. Don't try other implementations
            return;
        }

        // Default case
        EjbcaException ejbcaException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) { // added between v1 and v2, lacks an exact version
                try {
                    raMasterApi.keyRecoverWS(authenticationToken, username, certSNinHex, issuerDN);
                    // If no exceptions were thrown, recovery is complete
                    return;
                } catch (EjbcaException e) {
                    // Save the exception and continue with next implementation
                    ejbcaException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        // Unsuccessful on all implementations. Inform WS.
        if (ejbcaException != null) {
            throw ejbcaException;
        }
    }

    @Override
    public byte[] keyRecoverEnrollWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN, String password, String hardTokenSN)
            throws AuthorizationDeniedException, ApprovalException, CADoesntExistsException, EjbcaException, WaitingForApprovalException {
        AuthorizationDeniedException authorizationDeniedException = null;

        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 3) {
                try {
                    byte[] ret = raMasterApi.keyRecoverEnrollWS(authenticationToken, username, certSNinHex, issuerDN, password, hardTokenSN);
                    if (ret != null) {
                        return ret;
                    }
                } catch (AuthorizationDeniedException e) {
                    if (authorizationDeniedException == null) {
                        // Throw if all implementations fail
                        authorizationDeniedException = e;
                    }
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
    public List<CertificateWrapper> getLastCertChain(final AuthenticationToken authenticationToken, final String username) throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
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
    public void revokeCert(AuthenticationToken admin, BigInteger certserno, Date revocationdate, String issuerdn, int reason, boolean checkDate)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException {
        // Try remote first, since the certificate might be present in the RA database but the admin might not authorized to revoke it there
        CADoesntExistsException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 3) {
                try {
                    raMasterApi.revokeCert(admin, certserno, revocationdate, issuerdn, reason, checkDate);
                    // if it completed successfully, break
                    break;
                } catch (CADoesntExistsException e) {
                    caDoesntExistException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
    }

    @Override
    public void revokeCertWithMetadata(AuthenticationToken admin, CertRevocationDto certRevocationDto)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException, IllegalArgumentException, CertificateProfileDoesNotExistException {
        // Try remote first, since the certificate might be present in the RA database but the admin might not authorized to revoke it there
        CADoesntExistsException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 3) { // added between v3 and v4, lacks an exact version
                try {
                    raMasterApi.revokeCertWithMetadata(admin, certRevocationDto);
                    // if it completed successfully, break
                    break;
                } catch (CADoesntExistsException e) {
                    caDoesntExistException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
    }

    @Override
    public void revokeUser(final AuthenticationToken authenticationToken, final String username, final int reason, final boolean deleteUser) throws AuthorizationDeniedException, CADoesntExistsException,
        ApprovalException, WaitingForApprovalException, AlreadyRevokedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException, EjbcaException {
        // Try over all instances.
        boolean revoked = false;
        CADoesntExistsException caDoesntExistsException = null;
        NoSuchEndEntityException noSuchEndEntityException = null;
        ApprovalException approvalException = null;
        WaitingForApprovalException waitingForApprovalException = null;
        AlreadyRevokedException alreadyRevokedException = null;
        CouldNotRemoveEndEntityException couldNotRemoveEndEntityException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    raMasterApi.revokeUser(authenticationToken, username, reason, deleteUser);
                    revoked = true;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation.
                } catch (CADoesntExistsException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("CA for proxied request on CA could not be found: " + e.getMessage());
                    }
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                    // Just try next implementation.
                } catch (NoSuchEndEntityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "End entity for proxied request on CA could not be found: " + e.getMessage());
                    }
                    if (noSuchEndEntityException == null) {
                        noSuchEndEntityException = e;
                    }
                    // Just try next implementation.
                } catch (ApprovalException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "End entity for proxied request on CA is in approval process: " + e.getMessage());
                    }
                    if (approvalException == null) {
                        approvalException = e;
                    }
                    // Just try next implementation.
                } catch (WaitingForApprovalException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "End entity for proxied request on CA is in approval process: " + e.getMessage());
                    }
                    if (waitingForApprovalException == null) {
                        waitingForApprovalException = e;
                    }
                    // Just try next implementation.
                } catch (AlreadyRevokedException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "End entity for proxied request on CA is revoked already: " + e.getMessage());
                    }
                    if (alreadyRevokedException == null) {
                        alreadyRevokedException = e;
                    }
                    // Just try next implementation.
                } catch (CouldNotRemoveEndEntityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "End entity for proxied request on CA could not be removed: " + e.getMessage());
                    }
                	if (couldNotRemoveEndEntityException == null) {
                        couldNotRemoveEndEntityException = e;
                    }
                	// Just try next implementation.
                }
            }
        }
        if (!revoked) {
            if (caDoesntExistsException != null) {
                throw caDoesntExistsException;
            }
            if (approvalException != null) {
                throw approvalException;
            }
            if (waitingForApprovalException != null) {
                throw waitingForApprovalException;
            }
            if (alreadyRevokedException != null) {
                throw alreadyRevokedException;
            }
            if (couldNotRemoveEndEntityException != null) {
                throw couldNotRemoveEndEntityException;
            }
            if (noSuchEndEntityException != null) {
                throw noSuchEndEntityException;
            }
        }
    }

    @Override
    public CertificateStatus getCertificateStatus(AuthenticationToken authenticationToken, String issuerDN, BigInteger serno) throws CADoesntExistsException, AuthorizationDeniedException{
        CertificateStatus ret = null;
        // Try remote first, since the certificate might be present in the RA database but the admin might not authorized to revoke it there
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 3) {
                try {
                    ret = raMasterApi.getCertificateStatus(authenticationToken, issuerDN, serno);
                    if (ret != null) {
                        break;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (ret == null) {
            // This method should never return null according to the contract (javadoc)
            return CertificateStatus.NOT_AVAILABLE;
        }
        return ret;
    }

    @Override
    public boolean markForRecovery(AuthenticationToken authenticationToken, String username, String newPassword, CertificateWrapper cert, boolean localKeyGeneration) throws ApprovalException, CADoesntExistsException,
                                    AuthorizationDeniedException, WaitingForApprovalException, NoSuchEndEntityException, EndEntityProfileValidationException {
        boolean ret = false;
        final GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final boolean localKeyRecoveryThisNode = globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery();
        if (localKeyRecoveryThisNode) {
            localKeyGeneration = true;
        }

        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
                try {
                    ret = raMasterApi.markForRecovery(authenticationToken, username, newPassword, cert, localKeyGeneration);
                    if (ret) {
                        break;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (WaitingForApprovalException e) {
                    // If approval is required, the approving instance won't be able to set the flag in this database, so we set it anyway
                    // Enrollment won't be possible until UserData status is set to KeyRecovery by the requesting instance (at approval).
                    if (localKeyRecoveryThisNode) {
                        localNodeKeyRecoverySession.markAsRecoverableInternal(authenticationToken, cert, username);
                    }
                    throw e;
                }
            }
        }

        // If local key generation is enabled, we have to do this locally
        if (ret && localKeyRecoveryThisNode) {
            localNodeKeyRecoverySession.unmarkUser(authenticationToken, username);
            ret = localNodeKeyRecoverySession.markAsRecoverableInternal(authenticationToken, cert, username);
        }
        return ret;
    }

    @Override
    public boolean editUser(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation, boolean clearPwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 2) {
                try {
                    if (raMasterApi.editUser(authenticationToken, endEntityInformation, clearPwd)) {
                        // Successfully edited the user
                        return true;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        // Editing was unsuccessful
        return false;
    }

    @Override
    public boolean editUserWs(AuthenticationToken authenticationToken, UserDataVOWS userDataVOWS)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, CADoesntExistsException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, EjbcaException {
        CADoesntExistsException caDoesntExistException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    if (raMasterApi.editUserWs(authenticationToken, userDataVOWS)) {
                        // Successfully edited the user
                        return true;
                    }
                } catch (CADoesntExistsException e) {
                    caDoesntExistException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        // Editing was unsuccessful
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
        return false;
    }

    @Override
    public boolean keyRecoveryPossible(AuthenticationToken authenticationToken, Certificate cert, String username) {
        // Special case where local key generation is enabled
        GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery()) {
            EndEntityInformation storedEndEntity = searchUser(authenticationToken, username);
            if (storedEndEntity != null) {
                boolean authorized = false;
                authorized = isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY,
                        AccessRulesConstants.ENDENTITYPROFILEPREFIX + Integer.toString(storedEndEntity.getEndEntityProfileId()) + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                        AccessRulesConstants.REGULAR_RAFUNCTIONALITY + AccessRulesConstants.KEYRECOVERY_RIGHTS);
                return authorized && storedEndEntity.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY && localNodeKeyRecoverySession.existsKeys(EJBTools.wrap(cert));
            }
            return false;
        }

        // Default case (everything we need should be available in one instance database)
        boolean ret = false;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 1) {
                try {
                    ret = raMasterApi.keyRecoveryPossible(authenticationToken, cert, username);
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
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.getApprovalProfileForAction(authenticationToken, action, caId, certificateProfileId);
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
    public byte[] scepDispatch(final AuthenticationToken authenticationToken, final String operation, final String message, final String scepConfigurationAlias) throws CertificateEncodingException,
            CADoesntExistsException, NoSuchEndEntityException, CustomCertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException,
            SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, SignatureException, CertificateException,
            CertificateExtensionException, CertificateRenewalException, NoSuchAliasException, AuthorizationDeniedException {
        NoSuchAliasException caughtException = null;

        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 3) {
                try {
                    byte[] response;
                    try {
                        response = raMasterApi.scepDispatch(authenticationToken, operation, message, scepConfigurationAlias);
                        return response;
                        // Try all implementations before failing on this exception
                    } catch (NoSuchAliasException e) {
                        caughtException = e;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }

        if (caughtException != null) {
            throw caughtException;
        } else {
            return null;
        }
    }

    @Override
    public byte[] cmpDispatch(final AuthenticationToken authenticationToken, final byte[] pkiMessageBytes, final String cmpConfigurationAlias) throws NoSuchAliasException {
        NoSuchAliasException caughtException = null;

        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
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

    @Override
    public byte[] estDispatch(final String operation, final String alias, final X509Certificate cert, final String username, final String password,
            final byte[] requestBody) throws NoSuchAliasException,
            CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException  {
        NoSuchAliasException caughtNoAliasException = null;
        AuthenticationFailedException caughtAuthFailedException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 2) { // EST in version 2 and later
                try {
                    try {
                        return raMasterApi.estDispatch(operation, alias, cert, username, password, requestBody);
                    } catch (NoSuchAliasException e) {
                        //We might not have an alias in the current RaMasterApi, so let's try another. Let's store the exception in case we need it
                        //later though.
                        caughtNoAliasException = e;
                    } catch (AuthenticationFailedException e) {
                        // This will occur when WWW_AUTHENTICATE header (authentication method) is sent back to client. We don't want to
                        // interrupt this 'negotiation' unless all implementations fail (i.e. due to invalid authentication details).
                        caughtAuthFailedException = e;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }

        // either throw an exception or return null
        if (caughtNoAliasException != null) {
            throw caughtNoAliasException;
        } else if(caughtAuthFailedException != null){
            throw caughtAuthFailedException;
        } else {
        	// No suitable RaMasterAPIs were found?
        	log.info("No suitable RA Master APIs were found among the ones we have: " + raMasterApis.length);
        	if (log.isDebugEnabled()) {
        	    for (final RaMasterApi raMasterApi : raMasterApis) {
        	        log.info("isBackendAvailable: "+raMasterApi.isBackendAvailable() + ", apiVersion="+raMasterApi.getApiVersion()+", class: "+raMasterApi.getClass().getName());
        	    }
        	}
            return null;
        }
    }

    @Override
    public List<UserDataVOWS> findUserWS(AuthenticationToken authenticationToken, UserMatch usermatch, int maxNumberOfRows) throws
            AuthorizationDeniedException, IllegalQueryException, EjbcaException, EndEntityProfileNotFoundException {
        final List<UserDataVOWS> mergedResult = new ArrayList<>();
        EndEntityProfileNotFoundException eeProfileNotFoundException = null;
        boolean oneSucceeded = false;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()  && raMasterApi.getApiVersion() >= 4) {
                try {
                    List<UserDataVOWS> result = raMasterApi.findUserWS(authenticationToken, usermatch, maxNumberOfRows - mergedResult.size());
                    if (result != null) {
                        mergedResult.addAll(result);
                    }
                    if (mergedResult.size() >= maxNumberOfRows) {
                        return mergedResult;
                    }
                    oneSucceeded = true; // ignore exceptions if the search operation succeeds on one node (could still be an empty result)
                } catch (EndEntityProfileNotFoundException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("End entity profile not found on this peer. " + e.getMessage());
                    }
                    eeProfileNotFoundException = e;
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Trouble during back end invocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end invocation.", e);
                    }
                }
            }
        }
        if (!oneSucceeded && eeProfileNotFoundException != null) {
            throw eeProfileNotFoundException;
        }
        return mergedResult;
    }

    @Override
    public int getPublisherQueueLength(AuthenticationToken authenticationToken, String name) throws AuthorizationDeniedException, PublisherDoesntExistsException {
        PublisherDoesntExistsException publisherDoesntExistsException = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()  && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getPublisherQueueLength(authenticationToken, name);
                } catch (PublisherDoesntExistsException e) {
                    publisherDoesntExistsException = e;
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Trouble during back end invocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end invocation.", e);
                    }
                }
            }
        }
        if (publisherDoesntExistsException != null) {
            throw publisherDoesntExistsException;
        }
        throw new PublisherDoesntExistsException("No peer systems are available");
    }

    @Override
    public Collection<CertificateWrapper> getCertificateChain(final AuthenticationToken authenticationToken, int caid) throws AuthorizationDeniedException, CADoesntExistsException {
        CADoesntExistsException caDoesntExistException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getCertificateChain(authenticationToken, caid);
                } catch (CADoesntExistsException e) {
                    caDoesntExistException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
        return null;
    }

    @Override
    public int getCountOfCertificatesByExpirationTime(final AuthenticationToken authenticationToken, long days) throws AuthorizationDeniedException {
        int result = 0;
        for (RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    result += raMasterApi.getCountOfCertificatesByExpirationTime(authenticationToken, days);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return result;
    }

    @Override
    public void customLog(final AuthenticationToken authenticationToken, final String type, final String caName, final String username, final String certificateSn,
    		final String msg, final EventType event) throws AuthorizationDeniedException, CADoesntExistsException {
        AuthorizationDeniedException authorizationDeniedException = null;
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    raMasterApi.customLog(authenticationToken, type, caName, username, certificateSn, msg, event);
                    return;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization to write custom log entry for proxied request on CA was denied: " + e.getMessage());
                    }
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("CA to write custom log entry for proxied request on CA could not be found: " + e.getMessage());
                    }
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByUsername(final AuthenticationToken authenticationToken, final String username, final boolean onlyValid, final long now)
            throws AuthorizationDeniedException, CertificateEncodingException {
        AuthorizationDeniedException authorizationDeniedException = null;
        CertificateEncodingException certificateEncodingException = null;
        final Map<String, CertificateWrapper> result = new TreeMap<>();
        final List<CertificateWrapper> ret = new ArrayList<>();
        boolean oneSucceeded = false;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    final Collection<CertificateWrapper> certificates = raMasterApi.getCertificatesByUsername(authenticationToken, username, onlyValid, now);
                    for (CertificateWrapper certificate : certificates) {
                        result.put(CertTools.getFingerprintAsString(certificate.getCertificate()), certificate);
                    }
                    oneSucceeded = true;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    if (log.isDebugEnabled()) {
                        log.debug( "Authorization to get certificates by username for proxied request on CA was denied: " + e.getMessage());
                    }
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (CertificateEncodingException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Certificate found by username for proxied request on CA could not be encoded: " + e.getMessage());
                    }
                    if (certificateEncodingException == null) {
                        certificateEncodingException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (!oneSucceeded && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (!oneSucceeded && certificateEncodingException != null) {
            throw certificateEncodingException;
        }
        ret.addAll(result.values());
        return ret;
    }

    @Override
    public Map<String, Integer> getAvailableCertificateProfiles(final AuthenticationToken authenticationToken, final int entityProfileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException{
        // Try over all instances.
        final Map<String, Integer> result = new TreeMap<>();
        EndEntityProfileNotFoundException ejbcaException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    result.putAll(raMasterApi.getAvailableCertificateProfiles(authenticationToken, entityProfileId));
                    return result;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (EndEntityProfileNotFoundException e) {
                    log.debug("End entity profiles for proxied request on CA could not be found: " + e.getMessage());
                    if (ejbcaException == null) {
                        ejbcaException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (ejbcaException != null) {
            throw ejbcaException;
        }
        return result;
    }

    @Override
    public Map<String, Integer> getAvailableCasInProfile(final AuthenticationToken authenticationToken, final int entityProfileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
        EndEntityProfileNotFoundException endEntityProfileNotFoundException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getAvailableCasInProfile(authenticationToken, entityProfileId);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (EndEntityProfileNotFoundException e) {
                    log.debug("CAs associated with end entity profile " + entityProfileId + " for proxied request on CA could not be found: " + e.getMessage());
                    if (endEntityProfileNotFoundException == null) {
                        endEntityProfileNotFoundException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (endEntityProfileNotFoundException != null) {
        	throw endEntityProfileNotFoundException;
        }
        return new TreeMap<>();
    }

    @Override
    public CertificateWrapper getCertificate(final AuthenticationToken authenticationToken, final String certSNinHex, final String issuerDN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        CertificateWrapper result = null;
        AuthorizationDeniedException authorizationDeniedException = null;
        EjbcaException ejbcaException = null;
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    result = raMasterApi.getCertificate(authenticationToken, certSNinHex, issuerDN);
                    if (result != null) {
                    	return result;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    log.debug("Authorization denied for proxied request on CA: " + e.getMessage());
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    log.debug("CA for proxied request on CA could not be found: " + e.getMessage());
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                    // Just try next implementation.
                } catch (EjbcaException e) {
                    log.debug("Server side exception for proxied request on CA thrown: " + e.getMessage());
                    if (ejbcaException == null) {
                        ejbcaException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (ejbcaException != null) {
            throw ejbcaException;
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
        return result;
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTime(final AuthenticationToken authenticationToken, final long days,
            final int maxNumberOfResults, final int offset) throws AuthorizationDeniedException {
        final Map<String, CertificateWrapper> result = new TreeMap<>();
        final List<CertificateWrapper> ret = new ArrayList<>();
        int resultCount = 0;
        AuthorizationDeniedException authorizationDeniedException = null;
        boolean oneSucceeded = false;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    resultCount += raMasterApi.getCountOfCertificatesByExpirationTime(authenticationToken, days);
                    if (resultCount > offset && result.size() < maxNumberOfResults) {
                        int nodeOffset;
                        if (result.size() > 0) {
                            nodeOffset = 0;
                        } else {
                            nodeOffset = offset > resultCount ? (offset - resultCount) : offset;
                        }
                        final Collection<CertificateWrapper> certificates = raMasterApi.getCertificatesByExpirationTime(authenticationToken, days, (maxNumberOfResults - result.size()), nodeOffset);
                        for (CertificateWrapper certificate : certificates) {
                            if (result.size() < maxNumberOfResults) {
                                result.put(CertTools.getFingerprintAsString(certificate.getCertificate()), certificate);
                            }
                        }
                    }
                    oneSucceeded = true;
                } catch (AuthorizationDeniedException e) {
                    log.debug("Authorization was denied in getCertificatesByExpirationTime", e);
                    authorizationDeniedException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (!oneSucceeded && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        ret.addAll(result.values());
        return ret;
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTimeAndType(AuthenticationToken authenticationToken, long days, int certificateType, int maxNumberOfResults)
            throws AuthorizationDeniedException, EjbcaException {
        final Map<String, CertificateWrapper> result = new TreeMap<>();
        final List<CertificateWrapper> ret = new ArrayList<>();
        AuthorizationDeniedException authorizationDeniedException = null;
        boolean oneSucceeded = false;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    final Collection<CertificateWrapper> certificates = raMasterApi.getCertificatesByExpirationTimeAndType(authenticationToken, days, certificateType, maxNumberOfResults);
                    for (CertificateWrapper certificate : certificates) {
                        result.put(CertTools.getFingerprintAsString(certificate.getCertificate()), certificate);
                    }
                    oneSucceeded = true;
                } catch (AuthorizationDeniedException e) {
                    log.debug("Authorization was denied in getCertificatesByExpirationTime", e);
                    authorizationDeniedException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (!oneSucceeded && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        ret.addAll(result.values());
        return ret;
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTimeAndIssuer(AuthenticationToken authenticationToken, long days, String issuerDN, int maxNumberOfResults)
            throws AuthorizationDeniedException, EjbcaException {
        final Map<String, CertificateWrapper> result = new TreeMap<>();
        final List<CertificateWrapper> ret = new ArrayList<>();
        AuthorizationDeniedException authorizationDeniedException = null;
        boolean oneSucceeded = false;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    final Collection<CertificateWrapper> certificates = raMasterApi.getCertificatesByExpirationTimeAndIssuer(authenticationToken, days, issuerDN, maxNumberOfResults);
                    for (CertificateWrapper certificate : certificates) {
                        result.put(CertTools.getFingerprintAsString(certificate.getCertificate()), certificate);
                    }
                    oneSucceeded = true;
                } catch (AuthorizationDeniedException e) {
                    log.debug("Authorization was denied in getCertificatesByExpirationTime", e);
                    authorizationDeniedException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (!oneSucceeded && authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        ret.addAll(result.values());
        return ret;
    }

    @Override
    public Collection<CertificateWrapper> getLastCaChain(final AuthenticationToken authenticationToken, final String caName)
            throws AuthorizationDeniedException, CADoesntExistsException {
        final List<CertificateWrapper> result = new ArrayList<>();
        AuthorizationDeniedException authorizationDeniedException = null;
        CADoesntExistsException caDoesntExistException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            // Try locally since on RA local CAs are visible only for superadmin role (may be a bug!).
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getLastCaChain(authenticationToken, caName);
                } catch (AuthorizationDeniedException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization was denied to access CA with name " + caName + ": " + e.getMessage());
                    }
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("CA with name " + caName + " for proxied request on CA could not be found: " + e.getMessage());
                    }
                    if (caDoesntExistException == null) {
                        caDoesntExistException = e;
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
        return result;
    }

    @Override
    public byte[] processCertificateRequest(final AuthenticationToken authenticationToken, final String username, final String password, final String req, final int reqType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, EjbcaException, CesecoreException,
            CADoesntExistsException, CertificateExtensionException, InvalidKeyException, SignatureException, InvalidKeySpecException,
            NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, ParseException, ConstructionException,
            NoSuchFieldException, AuthStatusException, AuthLoginException {
        AuthorizationDeniedException authorizationDeniedException = null;
        NotFoundException notFoundException = null;
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.processCertificateRequest(authenticationToken, username, password, req, reqType, hardTokenSN, responseType);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    log.info("Authorization was denied to process certificate request for proxied request: " + e.getMessage());
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (NotFoundException e) {
                    log.info("User with name '" + username + "' for proxied request could not be found: " + e.getMessage());
                    if (notFoundException == null) {
                        notFoundException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    log.info("CA for proxied request could not be found:" + e.getMessage());
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                    // Just try next implementation
                } catch(ParseException | ConstructionException | NoSuchFieldException e) {
                	log.info("CV certificate request for proxied request could not processed:" + e.getMessage());
                    throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (notFoundException != null) {
            throw notFoundException;
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
        return null;
    }

    @Override
    public byte[] getLatestCrl(final AuthenticationToken authenticationToken, final String caName, final boolean deltaCRL)
            throws AuthorizationDeniedException, CADoesntExistsException {
        CADoesntExistsException caDoesntExistsException = null;
        byte[] result = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    // If there is a CA, there should be an initial CRL as well, assuming its not about an external CA.
                    result = raMasterApi.getLatestCrl(authenticationToken, caName, deltaCRL);
                    if (result != null) {
                        return result;
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("CA with name " + caName + " for proxied request on CA could not be found. " + e.getMessage());
                    }
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                }
            }
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
        return null;
    }

    @Override
    public byte[] getLatestCrlByIssuerDn(AuthenticationToken authenticationToken, String issuerDn, boolean deltaCRL) throws AuthorizationDeniedException, EjbcaException, CADoesntExistsException {
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getLatestCrlByIssuerDn(authenticationToken, issuerDn, deltaCRL);
                } catch (CADoesntExistsException e) {
                    caDoesntExistsException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
        return null;
    }

    @Override
    public Integer getRemainingNumberOfApprovals(final AuthenticationToken authenticationToken, final int requestId)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException {
        ApprovalException approvalException = null;
        ApprovalRequestExpiredException approvalRequestExpiredException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getRemainingNumberOfApprovals(authenticationToken, requestId);
                } catch (ApprovalException e) {
                    if (approvalException == null) {
                        approvalException = e;
                    }
                    // Just try next implementation
                } catch (ApprovalRequestExpiredException e) {
                    if (approvalRequestExpiredException == null) {
                        approvalRequestExpiredException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (approvalException != null) {
            throw approvalException;
        }
        if (approvalRequestExpiredException != null) {
            throw approvalRequestExpiredException;
        }
        return null;
    }

    @Override
    public Integer isApproved(final AuthenticationToken authenticationToken, final int approvalId)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException {
        ApprovalException approvalException = null;
        ApprovalRequestExpiredException approvalRequestExpiredException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.isApproved(authenticationToken, approvalId);
                } catch (ApprovalException e) {
                    if (approvalException == null) {
                        approvalException = e;
                    }
                    // Just try next implementation
                } catch (ApprovalRequestExpiredException e) {
                    if (approvalRequestExpiredException == null) {
                        approvalRequestExpiredException = e;
                    }
                    // Just try next implementation
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (approvalException != null) {
            throw approvalException;
        }
        if (approvalRequestExpiredException != null) {
            throw approvalRequestExpiredException;
        }
        return null;
    }

    @Override
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String... resource) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.isAuthorized(authenticationToken, resource);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return false; // If all requests have failed, authorization fails as well.
    }

    @Override
    public void republishCertificate(AuthenticationToken authenticationToken, String serialNumberInHex, String issuerDN)
            throws AuthorizationDeniedException, CADoesntExistsException, PublisherException, EjbcaException {
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    raMasterApi.republishCertificate(authenticationToken, serialNumberInHex, issuerDN);
                    break;
                } catch (CADoesntExistsException e) {
                    caDoesntExistsException = e;
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
    }

    @Override
    public byte[] generateOrKeyRecoverToken(final AuthenticationToken authenticationToken, final String username, final String password, final String hardTokenSN, final String keySpecification,
            final String keyAlgorithm) throws AuthorizationDeniedException, CADoesntExistsException, NotFoundException, EjbcaException {
    	AuthorizationDeniedException authorizationDeniedException = null;
    	CADoesntExistsException caDoesntExistException = null;
    	NotFoundException notFoundException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.generateOrKeyRecoverToken(authenticationToken, username, password, hardTokenSN, keySpecification, keyAlgorithm);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    log.info("Authorization was denied to access CA for proxied request: " + e.getMessage());
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    log.debug("CA for proxied request could not be found: " + e.getMessage());
                    if (caDoesntExistException == null) {
                    	caDoesntExistException = e;
                    }
                    // Just try next implementation
                } catch (NotFoundException e) {
                    log.debug("End entity with name " + username + " for proxied request could not be found: " + e.getMessage());
                    if (notFoundException == null) {
                    	notFoundException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (notFoundException != null) {
            throw notFoundException;
        }
        if (caDoesntExistException != null) {
            throw caDoesntExistException;
        }
        return null;
    }

    @Override
    public byte[] getEndEntityProfileAsXml(final AuthenticationToken authenticationToken, final int profileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException{
        AuthorizationDeniedException authorizationDeniedException = null;
        EndEntityProfileNotFoundException endEntityProfileNotFoundException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getEndEntityProfileAsXml(authenticationToken, profileId);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException  e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization was denied to access the End Entity Profile with ID " + profileId + " for proxied request on CA. " + e.getMessage());
                    }
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                }  catch (EndEntityProfileNotFoundException  e) {
                    if (log.isDebugEnabled()) {
                        log.debug("End Entity Profile with ID " + profileId +  " could not be found for proxied request on CA. " + e.getMessage());
                    }
                    if (endEntityProfileNotFoundException == null) {
                        endEntityProfileNotFoundException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (endEntityProfileNotFoundException != null) {
            throw endEntityProfileNotFoundException;
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return null;
    }

    @Override
    public byte[] getCertificateProfileAsXml(final AuthenticationToken authenticationToken, final int profileId)
            throws AuthorizationDeniedException, CertificateProfileDoesNotExistException{
        AuthorizationDeniedException authorizationDeniedException = null;
        CertificateProfileDoesNotExistException certificateProfileNotFoundException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getCertificateProfileAsXml(authenticationToken, profileId);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException  e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Authorization was denied to access the End Entity Profile with ID " + profileId + " for proxied request on CA. " + e.getMessage());
                    }
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                }  catch (CertificateProfileDoesNotExistException  e) {
                    if (log.isDebugEnabled()) {
                        log.debug("End Entity Profile with ID " + profileId +  " could not be found for proxied request on CA. " + e.getMessage());
                    }
                    if (certificateProfileNotFoundException == null) {
                        certificateProfileNotFoundException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (certificateProfileNotFoundException != null) {
            throw certificateProfileNotFoundException;
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        return null;
    }

    @Override
    public Collection<CertificateWrapper> processCardVerifiableCertificateRequest(final AuthenticationToken authenticationToken, final String username, final String password, final String cvcreq)
            throws AuthorizationDeniedException, CADoesntExistsException, UserDoesntFullfillEndEntityProfile, NotFoundException,
            ApprovalException, EjbcaException, WaitingForApprovalException, SignRequestException, CertificateExpiredException, CesecoreException {
        AuthorizationDeniedException authorizationDeniedException = null;
        NotFoundException notFoundException = null;
        CADoesntExistsException caDoesntExistsException = null;
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.processCardVerifiableCertificateRequest(authenticationToken, username, password, cvcreq);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                } catch (AuthorizationDeniedException e) {
                    log.info("Authorization was denied to process certificate request for proxied request: " + e.getMessage());
                    if (authorizationDeniedException == null) {
                        authorizationDeniedException = e;
                    }
                    // Just try next implementation
                } catch (NotFoundException e) {
                    log.info("User with name " + username + " for proxied request could not be found: " + e.getMessage());
                    if (notFoundException == null) {
                        notFoundException = e;
                    }
                    // Just try next implementation
                } catch (CADoesntExistsException e) {
                    log.info("CA for for poxied request cold not be found:" + e.getMessage());
                    if (caDoesntExistsException == null) {
                        caDoesntExistsException = e;
                    }
                    // Just try next implementation
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
        }
        if (notFoundException != null) {
            throw notFoundException;
        }
        if (caDoesntExistsException != null) {
            throw caDoesntExistsException;
        }
        return null;
    }

    @Override
    public AcmeAccount getAcmeAccountById(String accountId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeAccountById(accountId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public AcmeAccount getAcmeAccountByPublicKeyStorageId(final String publicKeyStorageId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeAccountByPublicKeyStorageId(publicKeyStorageId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public String persistAcmeAccount(final AcmeAccount acmeAccount) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.persistAcmeAccount(acmeAccount);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }
    
    @Override
    public AcmeOrder getAcmeOrderById(String orderId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeOrderById(orderId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public AcmeAuthorization getAcmeAuthorizationById(String authorizationId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeAuthorizationById(authorizationId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeAuthorizationsByOrderId(orderId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeAuthorizationsByAccountId(accountId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public Set<AcmeOrder> getAcmeOrdersByAccountId(final String accountId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeOrdersByAccountId(accountId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }
    
    @Override
    public Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(final String fingerprint) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getFinalizedAcmeOrdersByFingerprint(fingerprint);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }    
    
    @Override
    public String persistAcmeOrder(final AcmeOrder acmeOrder) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.persistAcmeOrder(acmeOrder);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<String> persistAcmeOrders(final List<AcmeOrder> acmeOrders) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.persistAcmeOrders(acmeOrders);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }
    
    @Override
    public void removeAcmeOrder(final String orderId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    raMasterApi.removeAcmeOrder(orderId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }
    
    @Override
    public void removeAcmeOrders(final List<String> orderIds) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    raMasterApi.removeAcmeOrders(orderIds);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }
    
    @Override
    public String persistAcmeAuthorization(AcmeAuthorization acmeAuthorization) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.persistAcmeAuthorization(acmeAuthorization);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public void persistAcmeAuthorizationList(List<AcmeAuthorization> acmeAuthorizations) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    raMasterApi.persistAcmeAuthorizationList(acmeAuthorizations);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }

    @Override
    public AcmeChallenge getAcmeChallengeById(String challengeId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeChallengeById(challengeId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public List<AcmeChallenge> getAcmeChallengesByAuthorizationId(String authorizationId) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.getAcmeChallengesByAuthorizationId(authorizationId);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public String persistAcmeChallenge(AcmeChallenge acmeChallenge) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    return raMasterApi.persistAcmeChallenge(acmeChallenge);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return null;
    }

    @Override
    public void persistAcmeChallengeList(List<AcmeChallenge> acmeChallenges) {
        for (RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 5) {
                try {
                    raMasterApi.persistAcmeChallengeList(acmeChallenges);
                }  catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
    }

    @Override
    public HashSet<String> getCaaIdentities(AuthenticationToken authenticationToken, int caId)
            throws AuthorizationDeniedException, CADoesntExistsException {
        for (RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.getCaaIdentities(authenticationToken, caId);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                }
            }
        }
        log.warn("All " + raMasterApis.length + " upstream peers are unavailable. Returning an empty set of CAA identities.");
        return new HashSet<String>();
    }

    @Override
    public byte[] addUserAndGenerateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd) throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
            AuthorizationDeniedException authorizationDeniedException = null;
        final GlobalConfiguration globalConfig = (GlobalConfiguration) localNodeGlobalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        // Local key pair generation requires special handling, generating keys and storing them locally while letting the CA issue the certificate using that key pair.
        if (endEntity.getKeyRecoverable() && globalConfig.getEnableKeyRecovery() && globalConfig.getLocalKeyRecovery()) {
            addUser(authenticationToken, endEntity, clearpwd);
            return generateKeyStore(authenticationToken, endEntity);
        }
        
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.addUserAndGenerateKeyStore(authenticationToken, endEntity, clearpwd);
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
    public byte[] addUserAndCreateCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd) throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        AuthorizationDeniedException authorizationDeniedException = null;
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable() && raMasterApi.getApiVersion() >= 4) {
                try {
                    return raMasterApi.addUserAndCreateCertificate(authenticationToken, endEntity, clearpwd);
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
}
