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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

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

    private RaMasterApi[] raMasterApis = null;
    private RaMasterApi[] raMasterApisLocalFirst = null;

    /** Default constructor */
    public RaMasterApiProxyBean() {
    }

    /** Constructor for use from JUnit tests */
    public RaMasterApiProxyBean(final RaMasterApi... raMasterApis) {
        this.raMasterApis = raMasterApis;
        final List<RaMasterApi> implementations = new ArrayList<RaMasterApi>(Arrays.asList(raMasterApis));
        Collections.reverse(implementations);
        this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
    }

    @PostConstruct
    private void postConstruct() {
        final List<RaMasterApi> implementations = new ArrayList<>();
        try {
            // Load peer implementation if available in this version of EJBCA
            final Class<?> c = Class.forName("org.ejbca.peerconnector.ra.RaMasterApiPeerImpl");
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
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        AccessSet merged = new AccessSet();
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
        final RaRequestsSearchResponse ret = new RaRequestsSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForApprovalRequests(authenticationToken, raRequestsSearchRequest));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public CertificateDataWrapper searchForCertificate(final AuthenticationToken authenticationToken, final String fingerprint) {
        CertificateDataWrapper ret = null;
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret = raMasterApi.searchForCertificate(authenticationToken, fingerprint);
                    if (ret != null) {
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
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken,
            RaCertificateSearchRequest raCertificateSearchRequest) {
        final RaCertificateSearchResponse ret = new RaCertificateSearchResponse();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    ret.merge(raMasterApi.searchForCertificates(authenticationToken, raCertificateSearchRequest));
                } catch (UnsupportedOperationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Trouble during back end envocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end envocation.", e);
                    }
                    // If the back end timed out due to a too heavy search we want to allow the client to retry with more fine grained criteria
                    ret.setMightHaveMoreResults(true);
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
                        log.debug("Trouble during back end envocation: " + e.getMessage());
                    }
                    // Just try next implementation
                } catch (RaMasterBackendUnavailableException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Timeout during back end envocation.", e);
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
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken) {
        final IdNameHashMap<EndEntityProfile> ret = new IdNameHashMap<EndEntityProfile>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final IdNameHashMap<EndEntityProfile> result = raMasterApi.getAuthorizedEndEntityProfiles(authenticationToken);
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
        final IdNameHashMap<CAInfo> ret = new IdNameHashMap<CAInfo>();
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
        final IdNameHashMap<CertificateProfile> ret = new IdNameHashMap<CertificateProfile>();
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
    public byte[] generateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity)
            throws AuthorizationDeniedException, EjbcaException {
        AuthorizationDeniedException authorizationDeniedException = null;
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
                }
            }
        }
        if (authorizationDeniedException != null) {
            throw authorizationDeniedException;
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
    public ApprovalProfile getApprovalProfileForAction(final AuthenticationToken authenticationToken, final int action, final int caId, final int certificateProfileId) throws AuthorizationDeniedException {
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
}
