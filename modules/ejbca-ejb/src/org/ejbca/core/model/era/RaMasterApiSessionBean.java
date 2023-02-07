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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.persistence.QueryTimeoutException;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificate.request.SshResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.EABConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.validation.CaaIdentitiesValidator;
import org.cesecore.keys.validation.DnsNameValidator;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.Validator;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberData;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalAcmeConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.GlobalCustomCssConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenMetaData;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.its.EtsiEcaOperationsSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.EndEntityProfileValidationRaException;
import org.ejbca.core.model.ra.KeyStoreGeneralRaException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.core.protocol.acme.AcmeAccount;
import org.ejbca.core.protocol.acme.AcmeAccountDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeCertificateDataWrapper;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeConfigurationSessionLocal;
import org.ejbca.core.protocol.acme.AcmeIdentifier;
import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.acme.AcmeOrderDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeProblemException;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.est.EstOperationsSessionLocal;
import org.ejbca.core.protocol.rest.EnrollPkcs10CertificateRequest;
import org.ejbca.core.protocol.scep.ScepMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;

/**
 * Implementation of the RaMasterApi that invokes functions at the local node.
 */
@Stateless//(mappedName = JndiConstants.APP_JNDI_PREFIX + "RaMasterApiSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class RaMasterApiSessionBean implements RaMasterApiSessionLocal {

    private static final Logger log = Logger.getLogger(RaMasterApiSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalExecutionSessionLocal approvalExecutionSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private AuthorizationSystemSessionLocal authorizationSystemSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateRequestSessionLocal certificateRequestSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;
    @EJB
    private CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
    @EJB
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EstOperationsSessionLocal estOperationsSessionLocal;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySessionLocal;
    @EJB
    private KeyStoreCreateSessionLocal keyStoreCreateSessionLocal;
    @EJB
    private NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession;
    @EJB
    private ScepMessageDispatcherSessionLocal scepMessageDispatcherSession;
    @EJB
    private SignSessionLocal signSessionLocal;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSessionLocal;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;
    @EJB
    private AcmeConfigurationSessionLocal acmeConfigurationSession;
    @EJB
    private AcmeAccountDataSessionLocal acmeAccountDataSession;
    @EJB
    private AcmeOrderDataSessionLocal acmeOrderDataSession;
    @EJB
    private AcmeAuthorizationDataSessionLocal acmeAuthorizationDataSession;
    @EJB
    private AcmeChallengeDataSessionLocal acmeChallengeDataSession;
    @EJB
    private EtsiEcaOperationsSessionLocal ecaOperationsSession;
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    /**
     * Defines the current RA Master API version.
     *
     * <p>List of versions:
     * <table>
     * <tr><th>0<td>=<td>6.6.0
     * <tr><th>1<td>=<td>6.8.0
     * <tr><th>2<td>=<td>6.11.0
     * <tr><th>3<td>=<td>6.12.0
     * <tr><th>4<td>=<td>6.14.0
     * <tr><th>5<td>=<td>6.15.0
     * <tr><th>6<td>=<td>7.0.0
     * <tr><th>7<td>=<td>7.1.0
     * <tr><th>8<td>=<td>7.3.0
     * <tr><th>9<td>=<td>7.4.1
     * <tr><th>10<td>=<td>7.4.2
     * <tr><th>11<td>=<td>7.5.0
     * <tr><th>12<td>=<td>7.5.1
     * <tr><th>13<td>=<td>7.9.0
     * <tr><th>14<td>=<td>7.10.0
     * <tr><th>15<td>=<td>7.11.0
     * </table>
     */
    private static final int RA_MASTER_API_VERSION = 15;

    /** Cached value of an active CA, so we don't have to list through all CAs every time as this is a critical path executed every time */
    private int activeCaIdCache = -1;

    @Override
    public boolean isBackendAvailable() {
        if (activeCaIdCache != -1) {
            CAInfo activeCa = caSession.getCAInfoInternal(activeCaIdCache);
            if (activeCa != null) {
                if (activeCa.getStatus() == CAConstants.CA_ACTIVE) {
                    return true;
                }
            } else {
                activeCaIdCache = -1;
                log.debug("Fail to get info for cached CA with ID " + activeCaIdCache);
            }
        }

        // If the cached activeCaIdCache was not active, or didn't exist, we move on to check all in the list
        for (int caId : caSession.getAllCaIds()) {
            if (caSession.getCAInfoInternal(caId).getStatus() == CAConstants.CA_ACTIVE) {
                activeCaIdCache = caId; // Remember this value for the next time
                return true;
            }
        }
        return false;
    }

    @Override
    public int getApiVersion() {
        return RA_MASTER_API_VERSION;
    }

    @Override
    public boolean isAuthorizedNoLogging(AuthenticationToken authenticationToken, String... resources) {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, resources);
    }

    @Override
    public RaAuthorizationResult getAuthorization(AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final HashMap<String, Boolean> accessRules = authorizationSession.getAccessAvailableToAuthenticationToken(authenticationToken);
        final int updateNumber = accessTreeUpdateSession.getAccessTreeUpdateNumber();
        return new RaAuthorizationResult(accessRules, updateNumber);
    }

    @Override
    @Deprecated
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException  {
        return authorizationSystemSession.getAccessSetForAuthToken(authenticationToken);
    }

    @Override
    @Deprecated
    public List<AccessSet> getUserAccessSets(final List<AuthenticationToken> authenticationTokens)  {
        final List<AccessSet> ret = new ArrayList<>();
        for (final AuthenticationToken authenticationToken : authenticationTokens) {
            try {
                ret.add(authorizationSystemSession.getAccessSetForAuthToken(authenticationToken));
            } catch (AuthenticationFailedException e) {
                // Always add, even if null. Otherwise the caller won't be able to determine which AccessSet belongs to which AuthenticationToken
                ret.add(null);
            }
        }
        return ret;
    }

    @Override
    public List<CAInfo> getAuthorizedCas(AuthenticationToken authenticationToken) {
        return caSession.getAuthorizedCaInfos(authenticationToken);
    }

    private LinkedHashMap<Integer, RaStyleInfo> getAllCustomRaCss() {
        GlobalCustomCssConfiguration globalCustomCssConfiguration = (GlobalCustomCssConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCustomCssConfiguration.CSS_CONFIGURATION_ID);
        // Returns an empty map if no CSS was found
        return globalCustomCssConfiguration.getRaStyleInfo();
    }

    @Override
    public LinkedHashMap<Integer,RaStyleInfo> getAllCustomRaStyles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        boolean authorizedToCssArchives = isAuthorizedNoLogging(authenticationToken,
                StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), StandardRules.VIEWROLES.resource());
        if (!authorizedToCssArchives) {
            throw new AuthorizationDeniedException(authenticationToken + " is not authorized to CSS archives");
        }
        return getAllCustomRaCss();
    }

    @Override
    public List<RaStyleInfo> getAvailableCustomRaStyles(AuthenticationToken authenticationToken, int hashCodeOfCurrentList) {
        List<RaStyleInfo> associatedCss = new ArrayList<>();
        LinkedHashMap<Integer, RaStyleInfo> allCssInfos = getAllCustomRaCss();
        List<Role> isMemberOf = roleSession.getRolesAuthenticationTokenIsMemberOf(authenticationToken);
        for (Role role : isMemberOf) {
            RaStyleInfo cssToAdd = allCssInfos.get(role.getStyleId());
            if (cssToAdd != null) {
                associatedCss.add(allCssInfos.get(role.getStyleId()));
            }
        }
        if (associatedCss.hashCode() == hashCodeOfCurrentList) {
            return null;
        }
        return associatedCss;
    }

    @Override
    public List<Role> getAuthorizedRoles(AuthenticationToken authenticationToken) {
        return roleSession.getAuthorizedRoles(authenticationToken);
    }
    
    @Override
    public List<Role> getRolesAuthenticationTokenIsMemberOf(AuthenticationToken authenticationToken) {
        return roleSession.getRolesAuthenticationTokenIsMemberOf(authenticationToken);
    }

    @Override
    public Role getRole(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        return roleSession.getRole(authenticationToken, roleId);
    }

    @Override
    public List<String> getAuthorizedRoleNamespaces(final AuthenticationToken authenticationToken, final int roleId) {
        // Skip roles that come from other peers if roleId is set
        try {
            if (roleId != Role.ROLE_ID_UNASSIGNED && getRole(authenticationToken, roleId) == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested role with ID " + roleId + " does not exist on this system, returning empty list of namespaces");
                }
                return new ArrayList<>();
            }
        } catch (AuthorizationDeniedException e) {
            // Should usually not happen
            if (log.isDebugEnabled()) {
                log.debug("Client " + authenticationToken + "was denied authorization to role with ID " + roleId + ", returning empty list of namespaces");
            }
            return new ArrayList<>();
        }
        return roleSession.getAuthorizedNamespaces(authenticationToken);
    }

    @Override
    public Map<String,RaRoleMemberTokenTypeInfo> getAvailableRoleMemberTokenTypes(final AuthenticationToken authenticationToken) {
        final Map<String,RaRoleMemberTokenTypeInfo> result = new HashMap<>();
        for (final String tokenType : AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes()) {
            // Disallow access to Public Access and CLI token types on the RA, as well as non-user-configurable token types such as AlwaysAllowLocal
            if (!AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType).isUserConfigurable() ||
                    PublicAccessAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) ||
                    CliAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType)) {
                continue;
            }

            final Map<String,Integer> stringToNumberMap = new HashMap<>();
            for (final Entry<String,AccessMatchValue> entry : AccessMatchValueReverseLookupRegistry.INSTANCE.getNameLookupRegistryForTokenType(tokenType).entrySet()) {
                stringToNumberMap.put(entry.getKey(), entry.getValue().getNumericValue());
            }
            final AccessMatchValue defaultValue = AccessMatchValueReverseLookupRegistry.INSTANCE.getDefaultValueForTokenType(tokenType);
            final boolean hasMatchTypes = !defaultValue.getAvailableAccessMatchTypes().isEmpty();

            result.put(tokenType, new RaRoleMemberTokenTypeInfo(stringToNumberMap, defaultValue.name(), defaultValue.isIssuedByCa(),
                    defaultValue.isIssuedByOauthProvider(), hasMatchTypes, hasMatchTypes ? defaultValue.getAvailableAccessMatchTypes().get(0).getNumericValue() : 0));

        }
        return result;
    }

    @Override
    public Role saveRole(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException, RoleExistsException {
        if (role.getRoleId() != Role.ROLE_ID_UNASSIGNED) {
            // Updating a role
            Role oldRole = roleSession.getRole(authenticationToken, role.getRoleId());
            if (oldRole == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Role with ID " + role.getRoleId() + " does not exist on this system, and will not be updated here. The role name to save was '" + role.getRoleNameFull() + "'");
                }
                return null; // not present on this system
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Persisting a role with ID " + role.getRoleId() + " and name '" + role.getRoleNameFull() + "'");
        }
        return roleSession.persistRole(authenticationToken, role);
    }

    @Override
    public boolean deleteRole(AuthenticationToken authenticationToken, int roleId) throws AuthorizationDeniedException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting role with ID " + roleId);
        }
        return roleSession.deleteRoleIdempotent(authenticationToken, roleId);
    }

    @Override
    public RoleMember getRoleMember(final AuthenticationToken authenticationToken, final int roleMemberId) throws AuthorizationDeniedException {
        return roleMemberSession.getRoleMember(authenticationToken, roleMemberId);
    }

    @Override
    public RoleMember saveRoleMember(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        if (log.isDebugEnabled()) {
            log.debug("Persisting a role member with ID " + roleMember.getRoleId() + " and match value '" + roleMember.getTokenMatchValue() + "'");
        }
        return roleMemberSession.persist(authenticationToken, roleMember);
    }

    @Override
    public boolean deleteRoleMember(AuthenticationToken authenticationToken, int roleId, int roleMemberId) throws AuthorizationDeniedException {
        if (log.isDebugEnabled()) {
            log.debug("Removing role member with ID " + roleMemberId + " from the role with ID " + roleId);
        }
        final RoleMember roleMember = roleMemberSession.getRoleMember(authenticationToken, roleMemberId);
        if (roleMember == null) {
            if (log.isDebugEnabled()) {
                log.debug("Can't delete role member with ID " + roleMemberId + " because it does not exist.");
            }
            log.info("Client " + authenticationToken + " failed to delete role member with ID " + roleMemberId + " because it does not exist.");
            return false;
        }
        // Sanity check that there's no ID collision
        if (roleMember.getRoleId() != roleId) {
            if (log.isDebugEnabled()) {
                log.debug("Role member has an unexpected Role ID " + roleMemberId + ". Role ID " + roleId);
            }
            return false;
        }
        return roleMemberSession.remove(authenticationToken, roleMemberId);
    }


    private ApprovalDataVO getApprovalDataNoAuth(final int id) {
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));

        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalSession.query(query, 0, 100, "", ""); // authorization checks are performed afterwards
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval request failed: " + e.getMessage(), e);
        }

        if (approvals.isEmpty()) {
            return null;
        }
        return approvals.iterator().next();
    }

    /** @param approvalId Calculated hash of the request (this somewhat confusing name is re-used from the ApprovalRequest class)
     * @return ApprovalDataVO or null if not found
     */
    private ApprovalDataVO getApprovalDataByRequestHash(final int approvalId) {
        final List<ApprovalDataVO> approvalDataVOs = approvalSession.findApprovalDataVO(approvalId);
        return approvalDataVOs.isEmpty() ? null : approvalDataVOs.get(0);
    }

    /** Gets the complete text representation of a request (unlike ApprovalRequest.getNewRequestDataAsText which doesn't do any database queries) */
    private List<ApprovalDataText> getRequestDataAsText(final AuthenticationToken authenticationToken, final ApprovalDataVO approval) {
        final ApprovalRequest approvalRequest = approval.getApprovalRequest();
        if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            return ((EditEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(caSession, endEntityProfileSession, certificateProfileSession);
        } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            return ((AddEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(caSession, endEntityProfileSession, certificateProfileSession);
        } else {
            return approvalRequest.getNewRequestDataAsText(authenticationToken);
        }
    }

    private RaEditableRequestData getRequestEditableData(final ApprovalDataVO approvalDataVO) {
        final ApprovalRequest approvalRequest = approvalDataVO.getApprovalRequest();
        final RaEditableRequestData editableData = new RaEditableRequestData();
        EndEntityInformation userData = null;
        if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            final EditEndEntityApprovalRequest req = (EditEndEntityApprovalRequest)approvalRequest;
            userData = req.getNewEndEntityInformation();
        } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            final AddEndEntityApprovalRequest req = (AddEndEntityApprovalRequest)approvalRequest;
            userData = req.getEndEntityInformation();
        }
        // TODO handle more types or approval requests? (ECA-5290)
        if (userData != null) {
            editableData.setUsername(userData.getUsername());
            editableData.setEmail(userData.getEmail());
            editableData.setSubjectDN(userData.getDN());
            editableData.setSubjectAltName(userData.getSubjectAltName());
            if (userData.getExtendedInformation() != null) {
                final ExtendedInformation ei = userData.getExtendedInformation();
                editableData.setSubjectDirAttrs(ei.getSubjectDirectoryAttributes());
            }
        }
        return editableData;
    }

    @Override
    public RaApprovalRequestInfo getApprovalRequest(final AuthenticationToken authenticationToken, final int id) {
        final ApprovalDataVO approvalDataVO = getApprovalDataNoAuth(id);
        if (approvalDataVO == null) {
            return null;
        }
        return getApprovalRequest(authenticationToken, approvalDataVO);
    }

    @Override
    public RaApprovalRequestInfo getApprovalRequestByRequestHash(final AuthenticationToken authenticationToken, final int approvalId) {
        final ApprovalDataVO approvalDataVO = getApprovalDataByRequestHash(approvalId);
        if (approvalDataVO == null) {
            return null;
        }
        return getApprovalRequest(authenticationToken, approvalDataVO);
    }

    private RaApprovalRequestInfo getApprovalRequest(final AuthenticationToken authenticationToken, final ApprovalDataVO approvalDataVO) {
        // By getting the CA we perform an implicit auth check
        String caName;
        if (approvalDataVO.getCAId() == ApprovalDataVO.ANY_CA) {
            caName = null;
        } else {
            try {
                final CAInfo cainfo = caSession.getCAInfo(authenticationToken, approvalDataVO.getCAId());
                if (cainfo != null) {
                    caName = cainfo.getName();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Approval request " + approvalDataVO.getId() + " references CA ID " + approvalDataVO.getCAId() + " which doesn't exist");
                    }
                    caName = "Missing CA ID " + approvalDataVO.getCAId();
                }
            } catch (AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Administrator " + authenticationToken + " was denied access to CA " + approvalDataVO.getCAId()
                            + ". Returning null instead of the approval with ID " + approvalDataVO.getId());
                }
                return null;
            }
        }

        final ApprovalRequest approvalRequest = approvalDataVO.getApprovalRequest();
        final String endEntityProfileName = endEntityProfileSession.getEndEntityProfileName(approvalDataVO.getEndEntityProfileId());
        final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(approvalDataVO.getEndEntityProfileId());
        final String certificateProfileName;
        if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            certificateProfileName = certificateProfileSession.getCertificateProfileName(((AddEndEntityApprovalRequest)approvalRequest).getEndEntityInformation().getCertificateProfileId());
        } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            certificateProfileName = certificateProfileSession.getCertificateProfileName(((EditEndEntityApprovalRequest)approvalRequest).getNewEndEntityInformation().getCertificateProfileId());
        } else {
            certificateProfileName = null;
        }

        // Get request data as text
        final List<ApprovalDataText> requestData = getRequestDataAsText(authenticationToken, approvalDataVO);

        // Editable data
        final RaEditableRequestData editableData = getRequestEditableData(approvalDataVO);
        final List<Role> rolesTokenIsMemberOf = roleSession.getRolesAuthenticationTokenIsMemberOf(authenticationToken);
        return new RaApprovalRequestInfo(authenticationToken, caName, endEntityProfileName, endEntityProfile, certificateProfileName, approvalDataVO, 
                requestData, editableData, rolesTokenIsMemberOf);
    }

    @Override
    public RaApprovalRequestInfo editApprovalRequest(final AuthenticationToken authenticationToken, final RaApprovalEditRequest edit) throws AuthorizationDeniedException {
        final int id = edit.getId();
        if (log.isDebugEnabled()) {
            log.debug("Editing approval request " + id + ". Administrator: " + authenticationToken);
        }
        final ApprovalDataVO approvalDataVO = getApprovalDataNoAuth(id);
        if (approvalDataVO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Approval Request with ID " + id + " not found in editApprovalRequest");
            }
            // This method may be called on multiple nodes (e.g. both locally on RA, and on multiple CAs),
            // so we must not throw any exceptions on the nodes where the request does not exist.
            return null;
        } else if (getApprovalRequest(authenticationToken, approvalDataVO) == null) { // Authorization check
            if (log.isDebugEnabled()) {
                log.debug("Authorization denied to approval request with ID " + id + " for administrator '" + authenticationToken + "'");
            }
            throw new AuthorizationDeniedException(authenticationToken + " is not authorized to the Request with ID " + id + " at this point");
        }

        if (approvalDataVO.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            throw new IllegalStateException("Was not in waiting for approval state");
        }

        if (!approvalDataVO.getApprovals().isEmpty()) {
            throw new IllegalStateException("Can't edit a request that has one or more approvals");
        }

        final ApprovalRequest approvalRequest = approvalDataVO.getApprovalRequest();
        final RaEditableRequestData editData = edit.getEditableData();

        // Can only edit approvals that we have requested, or that we are authorized to approve (ECA-5408)
        final AuthenticationToken requestAdmin = approvalRequest.getRequestAdmin();
        final boolean requestedByMe = requestAdmin != null && requestAdmin.equals(authenticationToken);
        if (requestedByMe) {
            if (log.isDebugEnabled()) {
                log.debug("Request (ID " + id + ") was created by this administrator, so authorization is granted. Editing administrator: '" + authenticationToken + "'");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Will perform approval authorization check, because request (ID " + id + ") was create by another administrator '" + requestAdmin + "'. Editing administrator: '" + authenticationToken + "'");
            }
            approvalExecutionSession.assertAuthorizedToApprove(authenticationToken, approvalDataVO);
        }

        if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            // Quick check for obviously illegal values
            if (StringUtils.isEmpty(editData.getUsername()) || StringUtils.isEmpty(editData.getSubjectDN())) {
                throw new IllegalArgumentException("Attempted to set Username or Subject DN to an empty value");
            }

            final AddEndEntityApprovalRequest addReq = (AddEndEntityApprovalRequest) approvalRequest;
            final EndEntityInformation userData = addReq.getEndEntityInformation();
            userData.setUsername(editData.getUsername());
            userData.setEmail(editData.getEmail());
            userData.setDN(editData.getSubjectDN());
            userData.setSubjectAltName(editData.getSubjectAltName());
            if (userData.getExtendedInformation() == null && editData.getSubjectDirAttrs() != null) {
                userData.setExtendedInformation(new ExtendedInformation());
            }
            final ExtendedInformation ei = userData.getExtendedInformation();
            ei.setSubjectDirectoryAttributes(editData.getSubjectDirAttrs());
        } else {
            // TODO implement more types of requests? (ECA-5290)
            if (log.isDebugEnabled()) {
                log.debug("Tried to edit approval request with ID " + id + " which is of an unsupported type: " + approvalRequest.getClass().getName());
            }
            throw new IllegalStateException("Editing of this type of request is not implemented: " + approvalRequest.getClass().getName());
        }

        try {
            approvalSession.editApprovalRequest(authenticationToken, id, approvalRequest);
        } catch (ApprovalException e) {
            // Shouldn't happen
            throw new IllegalStateException(e);
        }

        final int newCalculatedHash = approvalRequest.generateApprovalId();
        final Collection<ApprovalDataVO> newApprovalDataVOs = approvalSession.findApprovalDataVO(newCalculatedHash);
        if (newApprovalDataVOs.isEmpty()) {
            throw new IllegalStateException("Approval with calculated hash (approvalId) " + newCalculatedHash + " could not be found");
        }
        return getApprovalRequest(authenticationToken, newApprovalDataVOs.iterator().next());
    }

    @Override
    public void extendApprovalRequest(final AuthenticationToken authenticationToken, final int id, final long extendForMillis) throws AuthorizationDeniedException {
        final ApprovalDataVO approvalDataVO = getApprovalDataNoAuth(id);
        if (approvalDataVO == null) {
            if (log.isDebugEnabled()) {
                log.debug("Approval request with ID " + id + " does not exist on this node.");
            }
            return;
        }

        if (getApprovalRequest(authenticationToken, approvalDataVO) == null) { // Check read authorization (includes authorization to referenced CAs)
            if (log.isDebugEnabled()) {
                log.debug("Authorization denied to approval request ID " + id + " for " + authenticationToken);
            }
            throw new AuthorizationDeniedException(authenticationToken + " is not authorized to the Request with ID " + id + " at this point");
        }

        // Check specifically for approval authorization
        approvalExecutionSession.assertAuthorizedToApprove(authenticationToken, approvalDataVO);

        approvalSession.extendApprovalRequestNoAuth(authenticationToken, id, extendForMillis);
    }

    @Override
    public boolean addRequestResponse(final AuthenticationToken authenticationToken, final RaApprovalResponseRequest requestResponse)
            throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException, ApprovalRequestExecutionException,
            AdminAlreadyApprovedRequestException, SelfApprovalException, AuthenticationFailedException, EndEntityExistsException {
        final ApprovalDataVO approvalDataVO = getApprovalDataNoAuth(requestResponse.getId());
        if (approvalDataVO == null) {
            // Return false so the next master api backend can see if it can handle the approval
            return false;
        } else if (getApprovalRequest(authenticationToken, approvalDataVO) == null) { // Check read authorization (includes authorization to referenced CAs)
            if (log.isDebugEnabled()) {
                log.debug("Authorization denied to approval request ID " + requestResponse.getId() + " for " + authenticationToken);
            }
            throw new AuthorizationDeniedException(authenticationToken + " is not authorized to the Request with ID " + requestResponse.getId() + " at this point");
        }

        // Check specifically for approval authorization
        approvalExecutionSession.assertAuthorizedToApprove(authenticationToken, approvalDataVO);

        // Save the update request (needed if there are properties, e.g. checkboxes etc. in the partitions)
        approvalSession.updateApprovalRequest(approvalDataVO.getId(), requestResponse.getApprovalRequest());

        // Add the approval
        final Approval approval = new Approval(requestResponse.getComment(), requestResponse.getStepIdentifier(), requestResponse.getPartitionIdentifier());
        switch (requestResponse.getAction()) {
            case APPROVE:
                approvalExecutionSession.approve(authenticationToken, approvalDataVO.getApprovalId(), approval);
                return true;
            case REJECT:
                approvalExecutionSession.reject(authenticationToken, approvalDataVO.getApprovalId(), approval);
                return true;
            case SAVE:
                // All work is already done above
                return true;
            default:
                throw new IllegalStateException("Invalid action");
        }
    }

    @Override
    public RaRequestsSearchResponse searchForApprovalRequests(final AuthenticationToken authenticationToken, final RaRequestsSearchRequest request) {
        final RaRequestsSearchResponse response = new RaRequestsSearchResponse();
        final List<CAInfo> authorizedCas = getAuthorizedCas(authenticationToken);
        if (authorizedCas.size() == 0) {
            return response; // not authorized to any CAs. return empty response
        }
        final Map<Integer,String> caIdToNameMap = new HashMap<>();
        for (final CAInfo cainfo : authorizedCas) {
            caIdToNameMap.put(cainfo.getCAId(), cainfo.getName());
        }

        if (!request.isSearchingWaitingForMe() && !request.isSearchingPending() && !request.isSearchingHistorical() && !request.isSearchingExpired()) {
            return response; // not searching for anything. return empty response
        }

        final List<ApprovalDataVO> approvals;
        try {
            String endEntityProfileAuthorizationString = getEndEntityProfileAuthorizationString(authenticationToken);
            RAAuthorization raAuthorization = new RAAuthorization(authenticationToken, globalConfigurationSession,
                    authorizationSession, caSession, endEntityProfileSession);
            approvals = approvalSession.queryByStatus(request.isSearchingWaitingForMe() || request.isSearchingPending(), request.isSearchingHistorical(),
                    request.isSearchingExpired(), request.getStartDate(), request.getEndDate(), request.getExpiresBefore(), request.getCustomSearchSubjectDn(), request.getCustomSearchEmail(), 0, 100, raAuthorization.getCAAuthorizationString(), endEntityProfileAuthorizationString);
        } catch (AuthorizationDeniedException e) {
            // Not currently ever thrown by query()
            throw new IllegalStateException(e);
        }
        final Date now = new Date();

        if (log.isDebugEnabled()) {
            log.debug("Got " + approvals.size() + " approvals from Master API");
        }

        if (approvals.size() >= 100) {
            response.setMightHaveMoreResults(true);
        }

        final List<Role> rolesTokenIsMemberOf = getRolesAuthenticationTokenIsMemberOf(authenticationToken);
        for (final ApprovalDataVO approvalDataVO : approvals) {
            final List<ApprovalDataText> requestDataLite = approvalDataVO.getApprovalRequest().getNewRequestDataAsText(authenticationToken); // this method isn't guaranteed to return the full information
            final RaEditableRequestData editableData = getRequestEditableData(approvalDataVO);
            // We don't pass the end entity profile or certificate profile details for each approval request, when searching.
            // That information is only needed when viewing the details or editing a request.
            final RaApprovalRequestInfo ari = new RaApprovalRequestInfo(authenticationToken, caIdToNameMap.get(approvalDataVO.getCAId()), null, null, null,
                    approvalDataVO, requestDataLite, editableData, rolesTokenIsMemberOf);

            // Check if this approval should be included in the search results
            boolean include;
            if (request.getIncludeOtherAdmins()) {
                include = (request.isSearchingWaitingForMe() && ari.isWaitingForFirstApproval(now)) ||
                        (request.isSearchingPending() && ari.isInProgress(now)) ||
                        (request.isSearchingHistorical() && ari.isProcessed()) ||
                        (request.isSearchingExpired() && ari.isExpired(now));
            } else {                
                include = (request.isSearchingWaitingForMe() && ari.isWaitingForMe(rolesTokenIsMemberOf)) ||
                    (request.isSearchingPending() && ari.isPending(rolesTokenIsMemberOf)) ||
                    (request.isSearchingHistorical() && ari.isProcessed()) ||
                    (request.isSearchingExpired() && ari.isExpired(now));
            }

            if (include) {
                response.getApprovalRequests().add(ari);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Returning " + response.getApprovalRequests().size() + " approvals from search");
        }
        return response;
    }

    // TODO this method is copied from RAAuthorization because we couldn't use ComplexAccessControlSession.
    // We should find a way to use ComplexAccessControlSession here instead
    private String getEndEntityProfileAuthorizationString(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        // i.e approvals with EEP ApprovalDataVO.ANY_ENDENTITYPROFILE
        boolean authorizedToApproveCAActions = authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_APPROVECAACTION);
        // i.e approvals with EEP not ApprovalDataVO.ANY_ENDENTITYPROFILE
        boolean authorizedToApproveRAActions = authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_APPROVEENDENTITY);
        boolean authorizedToAudit = authorizationSession.isAuthorizedNoLogging(authenticationToken, AuditLogRules.VIEW.resource());
        boolean authorizedToViewApprovals = authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_VIEWAPPROVALS);
        if (!authorizedToApproveCAActions && !authorizedToApproveRAActions && !authorizedToAudit && !authorizedToViewApprovals) {
            throw new AuthorizationDeniedException(authenticationToken + " not authorized to query for approvals: ApproveCA, ApproveRA, Audit, ViewApprovals all false");
        }

        String endEntityAuth = null;
        GlobalConfiguration globalconfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (globalconfiguration.getEnableEndEntityProfileLimitations()){
            endEntityAuth = getAuthorizedEndEntityProfileIdsString(authenticationToken);
            if(authorizedToApproveCAActions && authorizedToApproveRAActions){
                endEntityAuth = getAuthorizedEndEntityProfileIdsString(authenticationToken);
                if(endEntityAuth != null){
                  endEntityAuth = "(" + getAuthorizedEndEntityProfileIdsString(authenticationToken) + " OR endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE + " ) ";
                }
            }
            else if (authorizedToApproveCAActions) {
                endEntityAuth = " endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE;
            }
            else if (authorizedToApproveRAActions) {
                endEntityAuth = getAuthorizedEndEntityProfileIdsString(authenticationToken);
            }

        }
        return endEntityAuth == null ? null : endEntityAuth.trim();
    }

    // TODO this method is copied from RAAuthorization because we couldn't use ComplexAccessControlSession.
    // Previous name: getEndEntityProfileAuthorizationString
    // We should find a way to use ComplexAccessControlSession here instead
    private String getAuthorizedEndEntityProfileIdsString(AuthenticationToken authenticationToken){
        StringBuilder authEndEntityProfileStringBuilder = null;
        Collection<Integer> profileIds = new ArrayList<>(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        Collection<Integer> results = getAuthorizedEndEntityProfileIds(authenticationToken, profileIds);
        results.retainAll(this.endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.APPROVE_END_ENTITY));
        for(Integer resultId : results) {
            if(authEndEntityProfileStringBuilder == null) {
                authEndEntityProfileStringBuilder = new StringBuilder(" endEntityProfileId = " + resultId);
            } else {
                authEndEntityProfileStringBuilder.append(" OR endEntityProfileId = ").append(resultId);
            }
        }
        if(authEndEntityProfileStringBuilder != null) {
            authEndEntityProfileStringBuilder = new StringBuilder("( " + authEndEntityProfileStringBuilder + " )");
        }
        return authEndEntityProfileStringBuilder != null ? authEndEntityProfileStringBuilder.toString() : null;
      }

    // TODO this method is copied from ComplexAccessControlSession. We should find a way to use ComplexAccessControlSession here instead
    private Collection<Integer> getAuthorizedEndEntityProfileIds(
            AuthenticationToken authenticationToken, Collection<Integer> availableEndEntityProfileId) {
        ArrayList<Integer> returnValues = new ArrayList<>();
        for (final Integer profileId : availableEndEntityProfileId) {
            if (authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileId + AccessRulesConstants.VIEW_END_ENTITY)) {
                returnValues.add(profileId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Administrator " + authenticationToken + " is not authorized to end entity profile: " + profileId);
                }
            }
        }
        return returnValues;
    }

    private boolean isNotAuthorizedToCert(final AuthenticationToken authenticationToken, final CertificateDataWrapper cdw) {
        if (!caSession.authorizedToCANoLogging(authenticationToken, cdw.getCertificateData().getIssuerDN().hashCode())) {
            return true;
        }
        // Check EEP authorization (allow an highly privileged admin, e.g. superadmin, that can access all profiles to ignore this check
        // so certificates can still be accessed by this admin even after a EEP has been removed.
        // Also, if we have access to the EMPTY profile, then we allow access to certificates with zero/null profile IDs, so they can at least be revoked.
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        if (authorizedEepIds.contains(EndEntityConstants.EMPTY_END_ENTITY_PROFILE)) {
            authorizedEepIds.add(EndEntityConstants.NO_END_ENTITY_PROFILE);
        }
        return !accessAnyEepAvailable && !authorizedEepIds.contains(cdw.getCertificateData().getEndEntityProfileIdOrZero());
    }

    @Override
    public CertificateDataWrapper searchForCertificate(final AuthenticationToken authenticationToken, final String fingerprint) {
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (cdw==null || isNotAuthorizedToCert(authenticationToken, cdw)) {
            return null;
        }
        return cdw;
    }

    @Override
    public List<CertificateWrapper> searchForCertificateChain(AuthenticationToken authenticationToken, String fingerprint) {
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (Objects.isNull(cdw) || isNotAuthorizedToCert(authenticationToken, cdw)) {
            return Collections.emptyList();
        }
        final List<CertificateWrapper> retval = new ArrayList<>();
        retval.add(cdw);
        appendCaChain(retval, cdw.getCertificate());
        return retval;
    }
    
    @Override
    public List<CertificateWrapper> searchForCertificateChainWithPreferredRoot(AuthenticationToken authenticationToken, String fingerprint, String rootSubjectDnHash) {
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (Objects.isNull(cdw) || isNotAuthorizedToCert(authenticationToken, cdw)) {
            return Collections.emptyList();
        }
        
        String issuerDn = CertTools.getIssuerDN(cdw.getCertificate());
        CAInfo internalCaInfo = caSession.getCAInfoInternal(issuerDn.hashCode());
        if(!(internalCaInfo instanceof X509CAInfo)) {
            return searchForCertificateChain(authenticationToken, fingerprint);
        }
        X509CAInfo caInfo = (X509CAInfo) internalCaInfo;
        PublicKey currentCaPublicKey = caInfo.getCertificateChain().get(0).getPublicKey();
        boolean signedByCurrentKey = true;
        try {
            cdw.getCertificate().verify(currentCaPublicKey);
        } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            log.debug("Certificate with fingerprint: " + fingerprint + " signed by old CA keys.");
            signedByCurrentKey = false;
        }
        List<CertificateWrapper> retval = new ArrayList<>();
        final List<String> alternateAliases = new ArrayList<>();
        
        if (caInfo.getAlternateCertificateChains()!=null && !caInfo.getAlternateCertificateChains().isEmpty()) {
            for (String rootSubjectDn: caInfo.getAlternateCertificateChains().keySet()) {
                alternateAliases.add(CertTools.getFingerprintAsString(rootSubjectDn.trim().getBytes()));
            }
        }
        
        if (signedByCurrentKey) {
            if (StringUtils.isEmpty(rootSubjectDnHash) || alternateAliases.isEmpty()) {
                for (Certificate cert: caInfo.getCertificateChain()) {
                    retval.add(EJBTools.wrap(cert));
                }
            } else {
                boolean chainFound = false;
                outer:
                for (Entry<String, List<String>> entry: caInfo.getAlternateCertificateChains().entrySet()) {
                    String curRootSubjectDnHash = CertTools.getFingerprintAsString(entry.getKey().trim().getBytes());
                    if (rootSubjectDnHash.equalsIgnoreCase(curRootSubjectDnHash)) {
                        chainFound = true;
                        for (String fp : entry.getValue()) {
                            // cross CA certificates are always stored in local db in CA node where the certs were uploaded
                            CertificateDataWrapper caCertWrapper = certificateStoreSession.getCertificateData(fp);
                            if(CertTools.getNotAfter(caCertWrapper.getCertificate()).before(new Date())) {
                                break outer;
                            }
                            retval.add(EJBTools.wrap(caCertWrapper.getCertificate()));
                        }
                        break;
                    }
                }
                
                if (!chainFound) { // fallback to default, if not found or cross chain is expired
                    for (Certificate cert: caInfo.getCertificateChain()) {
                        retval.add(EJBTools.wrap(cert));
                    } 
                }
            }
             
            // first one(leaf) is AcmeCertificateDataWrapper extending CertificateDataWrapper containing alternateAliases
            AcmeCertificateDataWrapper leafCert = new AcmeCertificateDataWrapper(cdw);
            leafCert.setAlternateChainAliases(alternateAliases);
            retval.add(0, leafCert);
                
        } else {
            // if old certificate i.e. CA rekeyed in meantime, alternate chains are not needed
            String defaultRootSubjectDnHash = CertTools.getFingerprintAsString(
                        CertTools.getIssuerDN(caInfo.getCertificateChain().get(caInfo.getCertificateChain().size()-1)).getBytes());
            if (StringUtils.isEmpty(rootSubjectDnHash)) {
                rootSubjectDnHash = defaultRootSubjectDnHash;
            }
            retval = appendRetiredCaChain(cdw, rootSubjectDnHash, defaultRootSubjectDnHash);
            if(retval.isEmpty()) {
                return searchForCertificateChain(authenticationToken, fingerprint);
            }
        }
        return retval;
    }
    
    private List<CertificateWrapper> appendRetiredCaChain(
            CertificateWrapper endEntityCertificate, String rootSubjectDnHash, String defaultRootSubjectDnHash) {
        
        List<CertificateWrapper> defaultChain = new ArrayList<>();
        // leaf certificate has least validity -> shortest range
        Date notBefore = CertTools.getNotBefore(endEntityCertificate.getCertificate());
        Date notAfter = CertTools.getNotAfter(endEntityCertificate.getCertificate());
        
        List<List<CertificateWrapper>> certificateChains = new ArrayList<>();
        List<CertificateWrapper> leafCertificate = new ArrayList<>();
        leafCertificate.add(endEntityCertificate);
        certificateChains.add(leafCertificate);
        
        for(int level=0; level<10; level++) {
            int candidateCertChainsSize = certificateChains.size();
            for(int i=0; i<candidateCertChainsSize; i++) {
                List<CertificateWrapper> curCertList = certificateChains.get(i);
                Certificate certificate = curCertList.get(curCertList.size()-1).getCertificate();
                final String issuerDN = CertTools.getIssuerDN(certificate);
                
                final Collection<Certificate> caCerts = certificateStoreSession.findCertificatesBySubject(issuerDN);
                if (CollectionUtils.isEmpty(caCerts)) {
                    log.info("No certificate found for CA with subjectDN: "+issuerDN);
                    continue;
                }
                for (final Certificate cert : caCerts) {
                    
                    if (CertTools.getNotBefore(cert).after(notBefore) || 
                            CertTools.getNotAfter(cert).before(notAfter)) {
                        continue;
                    }
                    
                    try {
                        certificate.verify(cert.getPublicKey());
                    } catch (Exception e) {
                        continue;
                    }
                    
                    if(CertTools.isSelfSigned(cert)) {
                        String curRootDnHash = CertTools.getFingerprintAsString(CertTools.getIssuerDN(cert).getBytes());
                        if(curRootDnHash.equalsIgnoreCase(rootSubjectDnHash)) {
                            curCertList.add(EJBTools.wrap(cert));
                            return curCertList;
                        } else if (curRootDnHash.equalsIgnoreCase(defaultRootSubjectDnHash)){
                            // backup, if contemporary cross chain was absent
                            List<CertificateWrapper> appendedCertChain = new ArrayList<>();
                            appendedCertChain.addAll(curCertList);
                            appendedCertChain.add(EJBTools.wrap(cert));
                            defaultChain = appendedCertChain;
                        }
                        else {
                            continue;
                        }
                    }
                    
                    List<CertificateWrapper> appendedCertChain = new ArrayList<>();
                    appendedCertChain.addAll(curCertList);
                    appendedCertChain.add(EJBTools.wrap(cert));
                    certificateChains.add(appendedCertChain);
                }
            }
            for(int i=0; i<candidateCertChainsSize; i++) {
                certificateChains.remove(0); // keep removing first one N times
            }
        }
            
        return defaultChain;
    }

    @Override
    public CertificateDataWrapper searchForCertificateByIssuerAndSerial(final AuthenticationToken authenticationToken, final String issuerDN, final String serNo) {
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateDataByIssuerAndSerno(issuerDN, new BigInteger(serNo, 16));
        if (cdw==null || isNotAuthorizedToCert(authenticationToken, cdw)) {
            return null;
        }
        return cdw;
    }

    @SuppressWarnings("unchecked")
    @Override
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest request) {
        final RaCertificateSearchResponse response = new RaCertificateSearchResponse();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        final List<String> issuerDns = new ArrayList<>();
        for (final int caId : authorizedLocalCaIds) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caId);
            final String caInfoIssuerDn = caInfo != null ? StringTools.strip(caInfo.getSubjectDN()) : "";
            if(caInfoIssuerDn.startsWith(CAInfo.CITS_SUBJECTDN_PREFIX)) {
                continue; // skip CITS CAs
            }
            final String issuerDn = CertTools.stringToBCDNString(caInfoIssuerDn);
            issuerDns.add(issuerDn);
        }
        if (issuerDns.isEmpty()) {
            // Empty response since there were no authorized CAs
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CAs and the search request will be dropped.");
            }
            return response;
        }
        // Check Certificate Profile authorization
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        final boolean accessAnyCpAvailable = authorizedCpIds.containsAll(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
        if (!request.getCpIds().isEmpty()) {
            authorizedCpIds.retainAll(request.getCpIds());
        }
        if (authorizedCpIds.isEmpty()) {
            // Empty response since there were no authorized Certificate Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CPs and the search request will be dropped.");
            }
            return response;
        }
        // Check End Entity Profile authorization
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        if (!request.getEepIds().isEmpty()) {
            authorizedEepIds.retainAll(request.getEepIds());
        }
        if (authorizedEepIds.isEmpty()) {
            // Empty response since there were no authorized End Entity Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested EEPs and the search request will be dropped.");
            }
            return response;
        }
        // If we have access to the EMPTY profile, then allow viewing certificates with zero/null profile IDs, so they can at least be revoked
        if (authorizedEepIds.contains(EndEntityConstants.EMPTY_END_ENTITY_PROFILE)) {
            authorizedEepIds.add(EndEntityConstants.NO_END_ENTITY_PROFILE);
            authorizedCpIds.add(CertificateProfileConstants.NO_CERTIFICATE_PROFILE);
        }

        // Copies the search certificates V1 request type to V2.
        final Query query = createQuery(authenticationToken, new RaCertificateSearchRequestV2(request), false, issuerDns, authorizedLocalCaIds, authorizedCpIds, accessAnyCpAvailable, authorizedEepIds, accessAnyEepAvailable);
        int maxResults = Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), request.getMaxResults());
        int offset = request.getPageNumber() * maxResults;
        query.setMaxResults(maxResults);
        query.setFirstResult(offset);

        /* Try to use the non-portable hint (depends on DB and JDBC driver) to specify how long in milliseconds the query may run. Possible behaviors:
         * - The hint is ignored
         * - A QueryTimeoutException is thrown
         * - A PersistenceException is thrown (and the transaction which don't have here is marked for roll-back)
         */
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }
        final List<String> fingerprints;
        try {
        	fingerprints = query.getResultList();
            for (final String fingerprint : fingerprints) {
                response.getCdws().add(certificateStoreSession.getCertificateData(fingerprint));
            }
            response.setMightHaveMoreResults(fingerprints.size()==maxResults);
            if (log.isDebugEnabled()) {
                log.debug("Certificate search query: page " + request.getPageNumber() + ", page size " + maxResults + ", count " + fingerprints.size() + " results. queryTimeout=" + queryTimeout + "ms");
            }
        } catch (QueryTimeoutException e) {
            // Query.toString() does not return the SQL query executed just a java object hash. If Hibernate is being used we can get it using:
            // query.unwrap(org.hibernate.Query.class).getQueryString()
            // We don't have access to hibernate when building this class though, all querying should be moved to the ejbca-entity package.
            // See ECA-5341
            final Query q = e.getQuery();
            String queryString = null;
            if (q != null) {
                queryString = q.toString();
            }
//            try {
//                queryString = e.getQuery().unwrap(org.hibernate.Query.class).getQueryString();
//            } catch (PersistenceException pe) {
//                log.debug("Query.unwrap(org.hibernate.Query.class) is not supported by JPA provider");
//            }
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was '" + queryString + "'. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        }
        return response;
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public RaCertificateSearchResponseV2 searchForCertificatesV2(AuthenticationToken authenticationToken, RaCertificateSearchRequestV2 request) {
        final RaCertificateSearchResponseV2 response = new RaCertificateSearchResponseV2();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        final List<String> issuerDns = new ArrayList<>();
        for (final int caId : authorizedLocalCaIds) {
            final String issuerDn = CertTools.stringToBCDNString(StringTools.strip(caSession.getCAInfoInternal(caId).getSubjectDN()));
            issuerDns.add(issuerDn);
        }
        if (issuerDns.isEmpty()) {
            // Empty response since there were no authorized CAs
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CAs and the search request will be dropped.");
            }
            return response;
        }
        // Check Certificate Profile authorization
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        final boolean accessAnyCpAvailable = authorizedCpIds.containsAll(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
        if (!request.getCpIds().isEmpty()) {
            authorizedCpIds.retainAll(request.getCpIds());
        }
        if (authorizedCpIds.isEmpty()) {
            // Empty response since there were no authorized Certificate Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CPs and the search request will be dropped.");
            }
            return response;
        }
        // Check End Entity Profile authorization
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        if (!request.getEepIds().isEmpty()) {
            authorizedEepIds.retainAll(request.getEepIds());
        }
        if (authorizedEepIds.isEmpty()) {
            // Empty response since there were no authorized End Entity Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested EEPs and the search request will be dropped.");
            }
            return response;
        }
        // If we have access to the EMPTY profile, then allow viewing certificates with zero/null profile IDs, so they can at least be revoked
        if (authorizedEepIds.contains(EndEntityConstants.EMPTY_END_ENTITY_PROFILE)) {
            authorizedEepIds.add(EndEntityConstants.NO_END_ENTITY_PROFILE);
            authorizedCpIds.add(CertificateProfileConstants.NO_CERTIFICATE_PROFILE);
        }

        final boolean countOnly = request.getPageNumber() == -1;
        final Query query = createQuery(authenticationToken, request, countOnly, issuerDns, authorizedLocalCaIds, authorizedCpIds, accessAnyCpAvailable, authorizedEepIds, accessAnyEepAvailable);;
        int maxResults = -1;
        int offset = -1;
        if (!countOnly) {
            maxResults = Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), request.getMaxResults());
            offset = (request.getPageNumber() - 1) * maxResults;
            query.setMaxResults(maxResults);
            query.setFirstResult(offset);
        }

        /* Try to use the non-portable hint (depends on DB and JDBC driver) to specify how long in milliseconds the query may run. Possible behaviors:
         * - The hint is ignored
         * - A QueryTimeoutException is thrown
         * - A PersistenceException is thrown (and the transaction which don't have here is marked for roll-back)
         */
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }
        final List<String> fingerprints;
        try {
            if (countOnly) {
                final long count = (long) query.getSingleResult();
                response.setTotalCount(count);
                if (log.isDebugEnabled()) {
                    log.debug("Certificate search count: " + count + ". queryTimeout=" + queryTimeout + "ms");
                }
            } else {
                fingerprints = query.getResultList();
                for (final String fingerprint : fingerprints) {
                    response.getCdws().add(certificateStoreSession.getCertificateData(fingerprint));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Certificate search query: page " + request.getPageNumber() + ", page size " + maxResults + ", count " + fingerprints.size() + " results. queryTimeout=" + queryTimeout + "ms");
                }
            }
        } catch (QueryTimeoutException e) {
            // Query.toString() does not return the SQL query executed just a java object hash. If Hibernate is being used we can get it using:
            // query.unwrap(org.hibernate.Query.class).getQueryString()
            // We don't have access to hibernate when building this class though, all querying should be moved to the ejbca-entity package.
            // See ECA-5341
            final Query q = e.getQuery();
            String queryString = null;
            if (q != null) {
                queryString = q.toString();
            }
//            try {
//                queryString = e.getQuery().unwrap(org.hibernate.Query.class).getQueryString();
//            } catch (PersistenceException pe) {
//                log.debug("Query.unwrap(org.hibernate.Query.class) is not supported by JPA provider");
//            }
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was '" + queryString + "'. " + e.getMessage());
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
        }
        return response;
    }
    
    private Query createQuery(final AuthenticationToken authenticationToken, final RaCertificateSearchRequestV2 request, final boolean countOnly, 
            final List<String> issuerDns, final List<Integer> authorizedLocalCaIds, 
            final List<Integer> authorizedCpIds, final boolean accessAnyCpAvailable, 
            final Collection<Integer> authorizedEepIds, final boolean accessAnyEepAvailable) {
        final String subjectDnSearchString = request.getSubjectDnSearchString();
        final String subjectAnSearchString = request.getSubjectAnSearchString();
        final String usernameSearchString = request.getUsernameSearchString();
        final String externalAccountIdSearchString = request.getExternalAccountIdSearchString();
        final String serialNumberSearchStringFromDec = request.getSerialNumberSearchStringFromDec();
        final String serialNumberSearchStringFromHex = request.getSerialNumberSearchStringFromHex();
        final StringBuilder sb = new StringBuilder("SELECT ");
        if (countOnly) {
            sb.append("count(*)");
        } else {
            sb.append("a.fingerprint");
        }
        sb.append(" FROM CertificateData a WHERE (a.issuerDN IN (:issuerDN))");
        if (!subjectDnSearchString.isEmpty() || !subjectAnSearchString.isEmpty() || !usernameSearchString.isEmpty() ||
                !serialNumberSearchStringFromDec.isEmpty() || !serialNumberSearchStringFromHex.isEmpty()
                || !StringUtils.isEmpty(externalAccountIdSearchString)) {
            sb.append(" AND (");
            boolean firstAppended = false;
            if (!subjectDnSearchString.isEmpty()) {
                sb.append("UPPER(a.subjectDN) LIKE :subjectDN");
                firstAppended = true;
            }
            if (!subjectAnSearchString.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                } else {
                    firstAppended = true;
                }
                sb.append("a.subjectAltName LIKE :subjectAltName");
            }
            if (!usernameSearchString.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                } else {
                    firstAppended = true;
                }
                sb.append("UPPER(a.username) LIKE :username");
            }
            if (!serialNumberSearchStringFromDec.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                } else {
                    firstAppended = true;
                }
                sb.append("a.serialNumber LIKE :serialNumberDec");
            }
            if (!serialNumberSearchStringFromHex.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                } else {
                    firstAppended = true;
                }
                sb.append("a.serialNumber LIKE :serialNumberHex");
            }
            if (!StringUtils.isEmpty(externalAccountIdSearchString)) {
                if (firstAppended) {
                    sb.append(" OR ");
                }
                sb.append("UPPER(a.accountBindingId) LIKE :accountBindingId");
            }
            sb.append(")");
        }
        // NOTE: notBefore is not indexed.. we might want to disallow such search.
        if (request.isIssuedAfterUsed()) {
            sb.append(" AND (a.notBefore > :issuedAfter)");
        }
        if (request.isIssuedBeforeUsed()) {
            sb.append(" AND (a.notBefore < :issuedBefore)");
        }
        if (request.isExpiresAfterUsed()) {
            sb.append(" AND (a.expireDate > :expiresAfter)");
        }
        if (request.isExpiresBeforeUsed()) {
            sb.append(" AND (a.expireDate < :expiresBefore)");
        }
        // NOTE: revocationDate is not indexed.. we might want to disallow such search.
        if (request.isRevokedAfterUsed()) {
            sb.append(" AND (a.revocationDate > :revokedAfter)");
        }
        if (request.isRevokedBeforeUsed()) {
            sb.append(" AND (a.revocationDate < :revokedBefore)");
        }
        if (request.isUpdatedAfterUsed()) {
            sb.append(" AND (a.updateTime > :updatedAfter)");
        }
        if (request.isUpdatedBeforeUsed()) {
            sb.append(" AND (a.updateTime < :updatedBefore)");
        }
        if (!request.getStatuses().isEmpty()) {
            sb.append(" AND (a.status IN (:status))");
            if ((request.getStatuses().contains(CertificateConstants.CERT_REVOKED) || request.getStatuses().contains(CertificateConstants.CERT_ARCHIVED)) &&
                    !request.getRevocationReasons().isEmpty()) {
                sb.append(" AND (a.revocationReason IN (:revocationReason))");
            }
        }
        // Don't constrain results to certain certificate profiles if root access is available and "any" CP is requested
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            sb.append(" AND (a.certificateProfileId IN (:certificateProfileId))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" EEP is requested
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            sb.append(" AND (a.endEntityProfileId IN (:endEntityProfileId))");
        }
        
        String orderProperty = request.getOrderProperty();
        String orderOperation = request.getOrderOperation();
        if (!countOnly && StringUtils.isNotBlank(orderProperty) && StringUtils.isNotBlank(orderOperation)) {
            orderOperation = orderOperation.trim();
            if("ASC".equalsIgnoreCase(orderOperation) || "DESC".equalsIgnoreCase(orderOperation)) {
                orderProperty = mapOrderColumn(orderProperty);
                if (orderProperty != null) { 
                    sb.append(" ORDER BY a.").append(orderProperty).append(" ").append(orderOperation);
                }
            } else {
                log.warn("Invalid order JPQL order operation '" + orderOperation + "'.");
            }
        } 
        
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("issuerDN", issuerDns);
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            query.setParameter("certificateProfileId", authorizedCpIds);
        }
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            query.setParameter("endEntityProfileId", authorizedEepIds);
        }
        if (log.isDebugEnabled()) {
            log.debug(" issuerDN: " + Arrays.toString(issuerDns.toArray()));
            if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
                log.debug(" certificateProfileId: " + Arrays.toString(authorizedCpIds.toArray()));
            } else {
                log.debug(" certificateProfileId: Any (even deleted) profile(s) due to root access.");
            }
            if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
                log.debug(" endEntityProfileId: " + Arrays.toString(authorizedEepIds.toArray()));
            } else {
                log.debug(" endEntityProfileId: Any (even deleted) profile(s) due to root access.");
            }
        }
        if (!subjectDnSearchString.isEmpty()) {
            if (request.isSubjectDnSearchExact()) {
                query.setParameter("subjectDN", subjectDnSearchString.toUpperCase());
            } else {
                query.setParameter("subjectDN", "%" + subjectDnSearchString.toUpperCase() + "%");
            }
        }
        if (!subjectAnSearchString.isEmpty()) {
            if (request.isSubjectAnSearchExact()) {
                query.setParameter("subjectAltName", subjectAnSearchString);
            } else {
                query.setParameter("subjectAltName", "%" + subjectAnSearchString + "%");
            }
        }
        if (!usernameSearchString.isEmpty()) {
            if (request.isUsernameSearchExact()) {
                query.setParameter("username", usernameSearchString.toUpperCase());
            } else {
                query.setParameter("username", "%" + usernameSearchString.toUpperCase() + "%");
            }
        }
        if (!serialNumberSearchStringFromDec.isEmpty()) {
            query.setParameter("serialNumberDec", serialNumberSearchStringFromDec);
            if (log.isDebugEnabled()) {
                log.debug(" serialNumberDec: " + serialNumberSearchStringFromDec);
            }
        }
        if (!serialNumberSearchStringFromHex.isEmpty()) {
            query.setParameter("serialNumberHex", serialNumberSearchStringFromHex);
            if (log.isDebugEnabled()) {
                log.debug(" serialNumberHex: " + serialNumberSearchStringFromHex);
            }
        }
        if (!StringUtils.isEmpty(externalAccountIdSearchString)) {
            if (request.isExternalAccountIdSearchExact()) {
                query.setParameter("accountBindingId", externalAccountIdSearchString.toUpperCase());
            } else {
                query.setParameter("accountBindingId", "%" + externalAccountIdSearchString.toUpperCase() + "%");
            }
        }
        if (request.isIssuedAfterUsed()) {
            query.setParameter("issuedAfter", request.getIssuedAfter());
        }
        if (request.isIssuedBeforeUsed()) {
            query.setParameter("issuedBefore", request.getIssuedBefore());
        }
        if (request.isExpiresAfterUsed()) {
            query.setParameter("expiresAfter", request.getExpiresAfter());
        }
        if (request.isExpiresBeforeUsed()) {
            query.setParameter("expiresBefore", request.getExpiresBefore());
        }
        if (request.isRevokedAfterUsed()) {
            query.setParameter("revokedAfter", request.getRevokedAfter());
        }
        if (request.isRevokedBeforeUsed()) {
            query.setParameter("revokedBefore", request.getRevokedBefore());
        }
        if (request.isUpdatedAfterUsed()) {
            query.setParameter("updatedAfter", request.getUpdatedAfter());
        }
        if (request.isUpdatedBeforeUsed()) {
            query.setParameter("updatedBefore", request.getUpdatedBefore());
        }
        if (!request.getStatuses().isEmpty()) {
            query.setParameter("status", request.getStatuses());
            if ((request.getStatuses().contains(CertificateConstants.CERT_REVOKED) || request.getStatuses().contains(CertificateConstants.CERT_ARCHIVED)) &&
                    !request.getRevocationReasons().isEmpty()) {
                query.setParameter("revocationReason", request.getRevocationReasons());
            }
        }
        return query;
    }
    
    private final String mapOrderColumn(final String property) {
        if (property != null) {
            switch (property.trim()) {
                case "USERNAME": return "username";
                case "ISSUER_DN": return "issuerDN";
                case "SUBJECT_DN": return "subjectDN";
                case "EXTERNAL_ACCOUNT_BINDING_ID": return "accountBindingId";
                case "END_ENTITY_PROFILE": return "endEntityProfileId";
                case "CERTIFICATE_PROFILE": return "certificateProfileId";
                case "STATUS": return "status";
                case "TAG": return "tag";
                case "TYPE": return "type";
                case "UPDATE_TIME": return "updateTime";
                case "ISSUED_DATE": return "notBefore";
                case "EXPIRE_DATE": return "expireDate";
                case "REVOCATION_DATE": return "revocationDate";
            }
        }
        log.warn("Invalid query order property '" + property + "'.");
        return null;
    }
    
    @Override
    public RaEndEntitySearchResponseV2 searchForEndEntitiesV2(AuthenticationToken authenticationToken,
            RaEndEntitySearchRequestV2 raEndEntitySearchRequest) {

        RaEndEntitySearchPaginationSummary searchSummary = null;
        String queryCacheKey = authenticationToken.getUniqueId() + raEndEntitySearchRequest.toString();
        if (raEndEntitySearchRequest.getPageNumber() != 1) {
            if (raEndEntitySearchRequest.getSearchSummary().isOnlyUpdateCache()) {
                // update for next page request
                searchSummary = (RaEndEntitySearchPaginationSummary)
                        RaMasterApiQueryCache.INSTANCE.getCachedResult(queryCacheKey);
                searchSummary.incrementCurrentIdentifierIndex();
                searchSummary.setCurrentIdentifierSearchOffset(0);
                // later may be used to update other props too
                RaMasterApiQueryCache.INSTANCE.updateCache(queryCacheKey, searchSummary);
                return null;
            }
            searchSummary = (RaEndEntitySearchPaginationSummary)
                    RaMasterApiQueryCache.INSTANCE.getCachedResult(queryCacheKey);

            if (raEndEntitySearchRequest.getSearchSummary().getCurrentIdentifierIndex() != 0) {
                // update in same page
                searchSummary.setCurrentIdentifierIndex(
                        raEndEntitySearchRequest.getSearchSummary().getCurrentIdentifierIndex());
                searchSummary.setCurrentIdentifierSearchOffset(0);
            }

        } else {
            // search identifier index, page offset are all initialized to zero
            searchSummary = raEndEntitySearchRequest.getSearchSummary();
            RaMasterApiQueryCache.INSTANCE.updateCache(queryCacheKey, searchSummary);
        }

        searchSummary.setMaxResultsPerPage(Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), raEndEntitySearchRequest.getMaxResults()));
        RaEndEntitySearchResponse searchResponse =
                searchForEndEntities(authenticationToken, raEndEntitySearchRequest,
                        searchSummary.getCurrentIdentifierSearchOffset(),
                raEndEntitySearchRequest.getSortOperation(),
                raEndEntitySearchRequest.getAdditionalConstraint(),
                searchSummary.getCurrentIdentifier());

        // update cache entry - page number, reference update
        searchSummary.setCurrentIdentifierSearchOffset(
                searchSummary.getCurrentIdentifierSearchOffset() + searchResponse.getEndEntities().size());
        searchSummary.incrementNextPageNumber();
        RaMasterApiQueryCache.INSTANCE.updateCache(queryCacheKey, searchSummary);

        return new RaEndEntitySearchResponseV2(searchResponse, searchSummary);
    }

    @Override
    public RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken, RaEndEntitySearchRequest request) {
        return searchForEndEntities(authenticationToken, request, -1, "", "", -1);
    }

    @SuppressWarnings("unchecked")
    private RaEndEntitySearchResponse searchForEndEntities(
            AuthenticationToken authenticationToken, RaEndEntitySearchRequest request, int currentQueryOffset,
            String sortingOperation, String additionalConstraintQuery, int additionalConstraintParam) {
        final RaEndEntitySearchResponse response = new RaEndEntitySearchResponse();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        if (authorizedLocalCaIds.isEmpty()) {
            // Empty response since there were no authorized CAs
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CAs and the search request will be dropped.");
            }
            return response;
        }
        // Check Certificate Profile authorization
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        final boolean accessAnyCpAvailable = authorizedCpIds.containsAll(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
        if (!request.getCpIds().isEmpty()) {
            authorizedCpIds.retainAll(request.getCpIds());
        }
        if (authorizedCpIds.isEmpty()) {
            // Empty response since there were no authorized Certificate Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CPs and the search request will be dropped.");
            }
            return response;
        }
        // Check End Entity Profile authorization
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
        if (!request.getEepIds().isEmpty()) {
            authorizedEepIds.retainAll(request.getEepIds());
        }
        if (authorizedEepIds.isEmpty()) {
            // Empty response since there were no authorized End Entity Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested EEPs and the search request will be dropped.");
            }
            return response;
        }
        final String subjectDnSearchString = request.getSubjectDnSearchString();
        final String subjectAnSearchString = request.getSubjectAnSearchString();
        final String usernameSearchString = request.getUsernameSearchString();
        final StringBuilder sb = new StringBuilder("SELECT a.username FROM UserData a WHERE (a.caId IN (:caId))");
        if (!subjectDnSearchString.isEmpty() || !subjectAnSearchString.isEmpty() || !usernameSearchString.isEmpty()) {
            sb.append(" AND (");
            boolean firstAppended = false;
            if (!subjectDnSearchString.isEmpty()) {
                sb.append("UPPER(a.subjectDN) LIKE :subjectDN");
                firstAppended = true;
            }
            if (!subjectAnSearchString.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                } else {
                    firstAppended = true;
                }
                sb.append("a.subjectAltName LIKE :subjectAltName");
            }
            if (!usernameSearchString.isEmpty()) {
                if (firstAppended) {
                    sb.append(" OR ");
                }
                sb.append("UPPER(a.username) LIKE :username");
            }
            sb.append(")");
        }

        if (request.isModifiedAfterUsed()) {
            sb.append(" AND (a.timeModified > :modifiedAfter)");
        }
        if (request.isModifiedBeforeUsed()) {
            sb.append(" AND (a.timeModified < :modifiedBefore)");
        }
        if (!request.getStatuses().isEmpty()) {
            sb.append(" AND (a.status IN (:status))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" CP is requested
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            sb.append(" AND (a.certificateProfileId IN (:certificateProfileId))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" EEP is requested
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            sb.append(" AND (a.endEntityProfileId IN (:endEntityProfileId))");
        }
        sb.append(additionalConstraintQuery);
        sb.append(sortingOperation);
        log.info("formed query: " + sb.toString());
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("caId", authorizedLocalCaIds);
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            query.setParameter("certificateProfileId", authorizedCpIds);
        }
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            query.setParameter("endEntityProfileId", authorizedEepIds);
        }
        if (log.isDebugEnabled()) {
            log.debug(" CA IDs: " + Arrays.toString(authorizedLocalCaIds.toArray()));
            if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
                log.debug(" certificateProfileId: " + Arrays.toString(authorizedCpIds.toArray()));
            } else {
                log.debug(" certificateProfileId: Any (even deleted) profile(s) due to root access.");
            }
            if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
                log.debug(" endEntityProfileId: " + Arrays.toString(authorizedEepIds.toArray()));
            } else {
                log.debug(" endEntityProfileId: Any (even deleted) profile(s) due to root access.");
            }
        }
        if (!subjectDnSearchString.isEmpty()) {
            if (request.isSubjectDnSearchExact()) {
                query.setParameter("subjectDN", subjectDnSearchString.toUpperCase());
            } else {
                query.setParameter("subjectDN", "%" + subjectDnSearchString.toUpperCase() + "%");
            }
        }
        if (!subjectAnSearchString.isEmpty()) {
            if (request.isSubjectAnSearchExact()) {
                query.setParameter("subjectAltName", subjectAnSearchString);
            } else {
                query.setParameter("subjectAltName", "%" + subjectAnSearchString + "%");
            }
        }
        if (!usernameSearchString.isEmpty()) {
            if (request.isUsernameSearchExact()) {
                query.setParameter("username", usernameSearchString.toUpperCase());
            } else {
                query.setParameter("username", "%" + usernameSearchString.toUpperCase() + "%");
            }
        }
        if (request.isModifiedAfterUsed()) {
            query.setParameter("modifiedAfter", request.getModifiedAfter());
        }
        if (request.isModifiedBeforeUsed()) {
            query.setParameter("modifiedBefore", request.getModifiedBefore());
        }
        if (!request.getStatuses().isEmpty()) {
            query.setParameter("status", request.getStatuses());
        }
        if(StringUtils.isNotEmpty(additionalConstraintQuery)) {
            query.setParameter("sortconstraint", additionalConstraintParam);
        }
        final int maxResults = Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), request.getMaxResults());
        query.setMaxResults(maxResults);
        if(currentQueryOffset!=-1) {
            // for v2 on multiple ca,cp,eep id in same page
            // maxResults is not updated for convenience
            query.setFirstResult(currentQueryOffset);
        } else {
            final int offset = maxResults * request.getPageNumber();
            query.setFirstResult(offset);
        }
        /* Try to use the non-portable hint (depends on DB and JDBC driver) to specify how long in milliseconds the query may run. Possible behaviors:
         * - The hint is ignored
         * - A QueryTimeoutException is thrown
         * - A PersistenceException is thrown (and the transaction which don't have here is marked for roll-back)
         */
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }
        log.info("query:" + query.toString());
        final List<String> usernames;
        try {
            usernames = query.getResultList();
            for (final String username : usernames) {
                response.getEndEntities().add(endEntityAccessSession.findUser(username));
            }
            response.setMightHaveMoreResults(usernames.size()==maxResults);
            if (log.isDebugEnabled()) {
                log.debug("Certificate search query: " + sb.toString() + " LIMIT " + maxResults + " \u2192 " + usernames.size() + " results. queryTimeout=" + queryTimeout + "ms");
            }
        } catch (QueryTimeoutException e) {
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was " + e.getQuery().toString() + ". " + e.getMessage());
            response.setMightHaveMoreResults(true);
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        }
        return response;
    }

    @Override
    public RaRoleSearchResponse searchForRoles(AuthenticationToken authenticationToken, RaRoleSearchRequest request) {
        // TODO optimize this (ECA-5721), should filter with a database query
        final List<Role> authorizedRoles = getAuthorizedRoles(authenticationToken);
        final RaRoleSearchResponse searchResponse = new RaRoleSearchResponse();
        final String searchString = request.getGenericSearchString();
        for (final Role role : authorizedRoles) {
            if (searchString == null || StringUtils.containsIgnoreCase(role.getRoleName(), searchString) ||
                    (role.getNameSpace() != null && StringUtils.containsIgnoreCase(role.getNameSpace(), searchString))) {
                searchResponse.getRoles().add(role);
            }
        }
        return searchResponse;
    }

    @SuppressWarnings("unchecked")
    @Override
    public RaRoleMemberSearchResponse searchForRoleMembers(AuthenticationToken authenticationToken, RaRoleMemberSearchRequest request) {
        final RaRoleMemberSearchResponse response = new RaRoleMemberSearchResponse();

        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        authorizedLocalCaIds.add(RoleMember.NO_ISSUER);
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }

        // Dito for roles
        final List<Integer> authorizedLocalRoleIds = new ArrayList<>();
        for (final Role role : roleSession.getAuthorizedRoles(authenticationToken)) {
            final int roleId = role.getRoleId();
            if (request.getRoleIds().isEmpty() || request.getRoleIds().contains(roleId)) {
                authorizedLocalRoleIds.add(roleId);
            }
        }
        if (request.getRoleIds().contains(RoleMember.NO_ROLE)) {
            authorizedLocalRoleIds.add(RoleMember.NO_ROLE);
        }

        // Token types
        final List<String> authorizedLocalTokenTypes = new ArrayList<>(getAvailableRoleMemberTokenTypes(authenticationToken).keySet());
        if (!request.getTokenTypes().isEmpty()) {
            authorizedLocalTokenTypes.retainAll(request.getTokenTypes());
        }

        if (authorizedLocalCaIds.isEmpty()) {
            log.debug("No authorized CAs found for client " + authenticationToken + ". Returning empty response in role member search");
            return response;
        }
        if (authorizedLocalRoleIds.isEmpty()) {
            log.debug("No authorized Roles found for client " + authenticationToken + " Returning empty response in role member search");
            return response;
        }
        if (authorizedLocalTokenTypes.isEmpty()) {
            log.debug("No authorized token types found for client " + authenticationToken + " Returning empty response in role member search");
            return response;
        }

        // Build query
        final StringBuilder sb = new StringBuilder("SELECT a FROM RoleMemberData a WHERE a.tokenIssuerId IN (:caId) AND a.roleId IN (:roleId) AND a.tokenType IN (:tokenType)");
        // TODO only search by exact tokenMatchValue if it seems to be a serial number?
        if (!StringUtils.isEmpty(request.getGenericSearchString())) {
            sb.append(" AND (a.tokenMatchValueColumn LIKE :searchStringInexact OR a.descriptionColumn LIKE :searchStringInexact)");
        }
        if (!request.getProviderIds().isEmpty()) {
            sb.append(" AND  a.tokenProviderId IN (:providerId) ");
        }
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("caId", authorizedLocalCaIds);
        query.setParameter("roleId", authorizedLocalRoleIds);
        query.setParameter("tokenType", authorizedLocalTokenTypes);
        if (!StringUtils.isEmpty(request.getGenericSearchString())) {
            //query.setParameter("searchString", request.getGenericSearchString());
            query.setParameter("searchStringInexact", request.getGenericSearchString() + '%');
        }
        if (!request.getProviderIds().isEmpty()) {
            query.setParameter("providerId", request.getProviderIds());
        }


        final int maxResults = getGlobalCesecoreConfiguration().getMaximumQueryCount();
        query.setMaxResults(maxResults);
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }

        // Execute
        try {
            final List<RoleMemberData> roleMemberDatas = query.getResultList();
            for (final RoleMemberData roleMemberData : roleMemberDatas) {
                response.getRoleMembers().add(roleMemberData.asValueObject());
            }
            response.setMightHaveMoreResults(roleMemberDatas.size()==maxResults);
            if (log.isDebugEnabled()) {
                log.debug("Role Member search query: " + sb.toString() + " LIMIT " + maxResults + " \u2192 " + roleMemberDatas.size() + " results. queryTimeout=" + queryTimeout + "ms");
            }
        } catch (QueryTimeoutException e) {
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was " + e.getQuery().toString() + ". " + e.getMessage());
            response.setMightHaveMoreResults(true);
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        }
        return response;
    }

    @Override
    public Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken) {
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        final Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        final Map<Integer, String> authorizedIdToNameMap = new HashMap<>();
        for (final Integer eepId : authorizedEepIds) {
            authorizedIdToNameMap.put(eepId, idToNameMap.get(eepId));
        }
        return authorizedIdToNameMap;
    }

    @Override
    public Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken) {
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        // There is no reason to return a certificate profile if it is not present in one of the authorized EEPs
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        final Set<Integer> cpIdsInAuthorizedEeps = new HashSet<>();
        for (final Integer eepId : authorizedEepIds) {
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(eepId);
            cpIdsInAuthorizedEeps.addAll(eep.getAvailableCertificateProfileIds());
        }
        authorizedCpIds.retainAll(cpIdsInAuthorizedEeps);
        final Map<Integer, String> idToNameMap = certificateProfileSession.getCertificateProfileIdToNameMap();
        final Map<Integer, String> authorizedIdToNameMap = new HashMap<>();
        for (final Integer cpId : authorizedCpIds) {
            authorizedIdToNameMap.put(cpId, idToNameMap.get(cpId));
        }
        return authorizedIdToNameMap;
    }

    @Override
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final String endEntityAccessRule) {
        Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, endEntityAccessRule);
        Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
        for (Integer id : ids){
            authorizedEndEntityProfiles.put(id, idToNameMap.get(id), endEntityProfileSession.getEndEntityProfile(id));
        }
        return authorizedEndEntityProfiles;
    }

    @Override
    public IdNameHashMap<CertificateProfile> getAllAuthorizedCertificateProfiles(AuthenticationToken authenticationToken){
        IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = getAuthorizedCertificateProfiles(authenticationToken, CertificateConstants.CERTTYPE_UNKNOWN);
        return authorizedCertificateProfiles;
    }
    
    @Override
    public RaCertificateProfileResponseV2 getCertificateProfileInfo(final AuthenticationToken authenticationToken, final String profileName) {
        final CertificateProfile profile = certificateProfileSession.getCertificateProfile(profileName);
        if (profile != null) {
            final Integer certProfileId = certificateProfileSession.getCertificateProfileId(profileName);
            final IdNameHashMap<CAInfo> caInfos = getAuthorizedCAInfos(authenticationToken);
            return RaCertificateProfileResponseV2.converter().toRaResponse(profile, caInfos, certProfileId);
        }
        return null;
    }
    
    @Override
    public IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken){
        IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = getAuthorizedCertificateProfiles(authenticationToken, CertificateConstants.CERTTYPE_ENDENTITY);
        return authorizedCertificateProfiles;
    }

    private IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken, int certificateProfileType) {
        IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();
        List<Integer> authorizedCertificateProfileIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, certificateProfileType);
        for (Integer certificateProfileId : authorizedCertificateProfileIds) {
            final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
            final String certificateProfileName = certificateProfileSession.getCertificateProfileName(certificateProfileId);
            authorizedCertificateProfiles.put(certificateProfileId, certificateProfileName, certificateProfile);
        }
        return authorizedCertificateProfiles;
    }

    @Override
    public CertificateProfile getCertificateProfile(int id) {
        return certificateProfileSession.getCertificateProfile(id);
    }

    @Override
    public IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken) {
        IdNameHashMap<CAInfo> authorizedCAInfos = new IdNameHashMap<>();
        List<CAInfo> authorizedCAInfosList = caSession.getAuthorizedAndNonExternalCaInfos(authenticationToken);
        for (CAInfo caInfo : authorizedCAInfosList){
            if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                authorizedCAInfos.put(caInfo.getCAId(), caInfo.getName(), caInfo);
            }
        }
        return authorizedCAInfos;
    }

    @Override
    public void checkSubjectDn(final AuthenticationToken admin, final EndEntityInformation endEntity) throws EjbcaException{
        KeyToValueHolder<CAInfo> caInfoEntry = getAuthorizedCAInfos(admin).get(endEntity.getCAId());
        if(caInfoEntry == null) {
            log.info("No authorized CAs found for " + admin);
            return;
        }
        try {
            certificateCreateSession.assertSubjectEnforcements(caInfoEntry.getValue(), endEntity);
        } catch (CertificateCreateException e) {
            // Wrapping the CesecoreException.errorCode
            throw new EjbcaException(e);
        }
    }
    
    private boolean populateEndEntityFromRestRequest(final AuthenticationToken admin, final EndEntityInformation endEntity) throws EjbcaException {
        // we ignore global configuration to "ignore EEP restriction" for REST

        // EEP
        Map<Integer, String> eeProfIdToNameMap = getAuthorizedEndEntityProfileIdsToNameMap(admin);
        Integer endEntityProfileId = null;
        for(Entry<Integer, String> entry: eeProfIdToNameMap.entrySet() ) {
            if(entry.getValue().equals(endEntity.getExtendedInformation().getCustomData(ExtendedInformation.END_ENTITY_PROFILE_NAME))) {
                endEntityProfileId = entry.getKey();
                break;
            }
        }
        
        if (endEntityProfileId == null) {
            throw new EjbcaException("End Entity Profile is invalid or unauthorized.");
        }
        endEntity.setEndEntityProfileId(endEntityProfileId);
        EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);

        // CA
        Integer caId = caSession.getAuthorizedCaNamesToIds(admin).get(endEntity.getExtendedInformation().getCustomData(ExtendedInformation.CA_NAME));
        if (caId == null) {
            throw new EjbcaException("CA name is invalid or unauthorized.");
        }
        endEntity.setCAId(caId);

        // Certificate profile id
        int certificateProfileId = certificateProfileSession
                .getCertificateProfileId(endEntity.getExtendedInformation().getCustomData(ExtendedInformation.CERTIFICATE_PROFILE_NAME));
        if (certificateProfileId == 0 || !endEntityProfile.getAvailableCertificateProfileIds().contains(certificateProfileId)) {
            throw new EjbcaException("Certificate profile name is invalid or unauthorized.");
        }
        endEntity.setCertificateProfileId(certificateProfileId);

        if (endEntityProfile.isSendNotificationUsed()) {
            if (StringUtils.isNotEmpty(endEntity.getEmail()) && endEntityProfile.isSendNotificationDefault()) {
                endEntity.setSendNotification(true);
            }
        }

        boolean isClearPwd = endEntityProfile.isClearTextPasswordUsed() && endEntityProfile.isClearTextPasswordDefault();

        endEntity.getExtendedInformation().getRawData().remove(ExtendedInformation.CUSTOMDATA + ExtendedInformation.MARKER_FROM_REST_RESOURCE);
        endEntity.getExtendedInformation().getRawData().remove(ExtendedInformation.CUSTOMDATA + ExtendedInformation.CA_NAME);
        endEntity.getExtendedInformation().getRawData().remove(ExtendedInformation.CUSTOMDATA + ExtendedInformation.CERTIFICATE_PROFILE_NAME);
        endEntity.getExtendedInformation().getRawData().remove(ExtendedInformation.CUSTOMDATA + ExtendedInformation.END_ENTITY_PROFILE_NAME);

        return isClearPwd;
    }

    @Override
    public boolean addUser(final AuthenticationToken admin, final EndEntityInformation endEntity, boolean isClearPwd) throws AuthorizationDeniedException,
            EjbcaException, WaitingForApprovalException{
        // only for REST to avoid fetching end entity profile contents to RA
        if(endEntity.getExtendedInformation()!=null && 
                endEntity.getExtendedInformation().getCustomData(ExtendedInformation.MARKER_FROM_REST_RESOURCE)!=null) {
            isClearPwd = populateEndEntityFromRestRequest(admin, endEntity);
        }
        
        try {
            endEntityManagementSession.addUser(admin, endEntity, isClearPwd);
        } catch (CesecoreException e) {
            //Wrapping the CesecoreException.errorCode
            throw new EjbcaException(e);
        } catch (EndEntityProfileValidationException e) {
            //Wraps @WebFault Exception based with @NonSensitive EjbcaException based
            throw new EndEntityProfileValidationRaException(e);
        }
        return endEntityAccessSession.findUser(endEntity.getUsername()) != null;
    }

    @Override
    public boolean addUserFromWS(final AuthenticationToken authenticationToken, UserDataVOWS userDataVOWS, final boolean isClearPwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, IllegalNameException, CertificateSerialNumberException, EjbcaException {
        EndEntityInformation endEntityInformation = ejbcaWSHelperSession.convertUserDataVOWS(authenticationToken, userDataVOWS);
        //Perform any request pre-processing on the end entity
        CAInfo cainfo = caSession.getCAInfoInternal(endEntityInformation.getCAId());
        if(cainfo.getCAType() == CAInfo.CATYPE_X509) {
            String preProcessorClass = ((X509CAInfo) cainfo).getRequestPreProcessor();
            if (!StringUtils.isEmpty(preProcessorClass)) {
                try {
                    ExtendedUserDataHandler extendedUserDataHandler = (ExtendedUserDataHandler) Class.forName(preProcessorClass)
                            .getDeclaredConstructor().newInstance();
                    endEntityInformation = extendedUserDataHandler.processEndEntityInformation(endEntityInformation,
                            certificateProfileSession.getCertificateProfileName(endEntityInformation.getCertificateProfileId()));
                } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IllegalArgumentException
                        | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                    throw new IllegalStateException("Request Preprocessor implementation " + preProcessorClass + " could not be instansiated.");
                }
            }
        }
        
        endEntityManagementSession.addUser(authenticationToken, endEntityInformation, isClearPwd);
        return endEntityAccessSession.findUser(endEntityInformation.getUsername()) != null;
    }


    @Override
    public void deleteUser(final AuthenticationToken admin, final String username) throws AuthorizationDeniedException{
        try {
            endEntityManagementSession.deleteUser(admin, username);
        } catch (NoSuchEndEntityException | CouldNotRemoveEndEntityException e) {
            log.info(e.getMessage());
        }
    }

    @Override
    public EndEntityInformation searchUser(final AuthenticationToken admin, String username) {
        try {
            return endEntityAccessSession.findUser(admin, username);
        } catch (AuthorizationDeniedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Not authorized to end entity '" + username + "'");
            }
            return null;
        }
    }
    
    @Override
    public EndEntityInformation searchUserWithoutViewEndEntityAccessRule(final AuthenticationToken admin, String username) {
        try {
            return endEntityAccessSession.findUserWithoutViewEndEntityAccessRule(admin, username);
        } catch (AuthorizationDeniedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Not authorized to end entity '" + username + "'");
            }
            return null;
        }
    }

    @Override
    public boolean canEndEntityEnroll(AuthenticationToken authenticationToken, String username) {
        return endEntityAuthenticationSessionLocal.isAllowedToEnroll(authenticationToken, username);
    }

    @Override
    public void checkUserStatus(AuthenticationToken admin, String username, String password) throws NoSuchEndEntityException, AuthStatusException, AuthLoginException {
        endEntityAuthenticationSessionLocal.authenticateUser(admin, username, password);
    }

    @Override
    public void finishUserAfterLocalKeyRecovery(final AuthenticationToken authenticationToken, final String username, final String password) throws AuthorizationDeniedException, EjbcaException {
        EndEntityInformation userData = endEntityAccessSession.findUser(username);
        if (userData == null) {
            throw new EjbcaException(ErrorCode.USER_NOT_FOUND, "User '"+username+"' does not exist");
        }
        if (userData.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY) {
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, "User '"+username+"' is not in KEYRECOVERY status");
        }
        try {
            final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (globalConfig.getEnableEndEntityProfileLimitations()) {
                // Check if administrator is authorized to perform key recovery
                endEntityAuthenticationSessionLocal.isAuthorizedToEndEntityProfile(authenticationToken, userData.getEndEntityProfileId(), AccessRulesConstants.KEYRECOVERY_RIGHTS);
            }
            endEntityAuthenticationSessionLocal.authenticateUser(authenticationToken, username, password);
            final boolean shouldFinishUser = caSession.getCAInfo(authenticationToken, userData.getCAId()).getFinishUser();
            if (shouldFinishUser) {
                    endEntityManagementSession.finishUser(userData);
            }

            userData = endEntityAccessSession.findUser(username);
            if (userData.getStatus() == EndEntityConstants.STATUS_GENERATED) {
                // We require keyrecovery access. The operation below should not require edit access, so we use an AlwaysAllowLocalAuthenticationToken
                endEntityManagementSession.setClearTextPassword(new AlwaysAllowLocalAuthenticationToken(
                        new UsernamePrincipal("Implicit authorization from key recovery operation to reset password.")), username, null);
            }
        } catch (NoSuchEndEntityException | EndEntityProfileValidationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] generateKeyStore(final AuthenticationToken admin, final EndEntityInformation endEntity) throws AuthorizationDeniedException, EjbcaException {
        KeyStore keyStore;
        try {
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntity.getEndEntityProfileId());
            boolean useKeyRecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            EndEntityInformation data = endEntityAccessSession.findUser(endEntity.getUsername());
            if (data == null) {
                throw new EjbcaException(ErrorCode.USER_NOT_FOUND, "User '"+endEntity.getUsername()+"' does not exist");
            }
            final boolean saveKeysFlag = data.getKeyRecoverable() && useKeyRecovery && (data.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
            final boolean loadKeysFlag = (data.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && useKeyRecovery;
            final boolean reuseCertificateFlag = endEntityProfile.getReUseKeyRecoveredCertificate();
            ExtendedInformation ei = endEntity.getExtendedInformation();
            if (ei == null) {
                // ExtendedInformation is optional, and we don't want any NPEs here
            	// Make it easy for ourselves and create a default one if there is none in the end entity
                ei = new ExtendedInformation();
            }
            final String encodedValidity = ei.getCertificateEndTime();
            final Date notAfter = encodedValidity == null ? null :
                ValidityDate.getDate(encodedValidity, new Date(), isNotAfterInclusive(admin, endEntity));
            keyStore = keyStoreCreateSessionLocal.generateOrKeyRecoverToken(admin, // Authentication token
                    endEntity.getUsername(), // Username
                    endEntity.getPassword(), // Enrollment code
                    endEntity.getCAId(), // The CA signing the private keys
                    ei.getKeyStoreAlgorithmSubType(), // Keylength
                    ei.getKeyStoreAlgorithmType(), // Signature algorithm
                    null, // Not valid before
                    notAfter, // Not valid after
                    endEntity.getTokenType(), // Type of token
                    loadKeysFlag, // Perform key recovery?
                    saveKeysFlag, // Save private keys?
                    reuseCertificateFlag, // Reuse recovered cert?
                    endEntity.getEndEntityProfileId()); // Identifier for end entity
        } catch (KeyStoreException | InvalidAlgorithmParameterException | CADoesntExistsException | IllegalKeyException
                | CertificateCreateException | IllegalNameException | CertificateRevokeException | CertificateSerialNumberException
                | CryptoTokenOfflineException | IllegalValidityException | CAOfflineException | InvalidAlgorithmException
                | CustomCertificateSerialNumberException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException
                | EndEntityProfileValidationException | CertificateSignatureException | NoSuchEndEntityException e) {
            throw new KeyStoreGeneralRaException(e);
        }
        if (endEntity.getTokenType() == EndEntityConstants.TOKEN_SOFT_PEM){
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                outputStream.write(KeyTools.getSinglePemFromKeyStore(keyStore, endEntity.getPassword().toCharArray()));
                return outputStream.toByteArray();
            } catch (IOException | CertificateEncodingException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        } else{
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                keyStore.store(outputStream, endEntity.getPassword().toCharArray());
                return outputStream.toByteArray();
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        }
        return null;
    }
    
    @Override
    public byte[] generateKeyStoreWithoutViewEndEntityAccessRule(final AuthenticationToken admin, final EndEntityInformation endEntity) throws AuthorizationDeniedException, EjbcaException {
        KeyStore keyStore;
        try {
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntity.getEndEntityProfileId());
            boolean useKeyRecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            EndEntityInformation data = endEntityAccessSession.findUser(endEntity.getUsername());
            if (data == null) {
                throw new EjbcaException(ErrorCode.USER_NOT_FOUND, "User '"+endEntity.getUsername()+"' does not exist");
            }
            final boolean saveKeysFlag = data.getKeyRecoverable() && useKeyRecovery && (data.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
            final boolean loadKeysFlag = (data.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && useKeyRecovery;
            final boolean reuseCertificateFlag = endEntityProfile.getReUseKeyRecoveredCertificate();
            ExtendedInformation ei = endEntity.getExtendedInformation();
            if (ei == null) {
                // ExtendedInformation is optional, and we don't want any NPEs here
                // Make it easy for ourselves and create a default one if there is none in the end entity
                ei = new ExtendedInformation();
            }
            final String encodedValidity = ei.getCertificateEndTime();
            final Date notAfter = encodedValidity == null ? null :
                ValidityDate.getDate(encodedValidity, new Date(), isNotAfterInclusive(admin, endEntity));
            keyStore = keyStoreCreateSessionLocal.generateOrKeyRecoverTokenWithoutViewEndEntityAccessRule(admin, // Authentication token
                    endEntity.getUsername(), // Username
                    endEntity.getPassword(), // Enrollment code
                    endEntity.getCAId(), // The CA signing the private keys
                    ei.getKeyStoreAlgorithmSubType(), // Keylength
                    ei.getKeyStoreAlgorithmType(), // Signature algorithm
                    null, // Not valid before
                    notAfter, // Not valid after
                    endEntity.getTokenType(), // Type of token
                    loadKeysFlag, // Perform key recovery?
                    saveKeysFlag, // Save private keys?
                    reuseCertificateFlag, // Reuse recovered cert?
                    endEntity.getEndEntityProfileId()); // Identifier for end entity
        } catch (KeyStoreException | InvalidAlgorithmParameterException | CADoesntExistsException | IllegalKeyException
                | CertificateCreateException | IllegalNameException | CertificateRevokeException | CertificateSerialNumberException
                | CryptoTokenOfflineException | IllegalValidityException | CAOfflineException | InvalidAlgorithmException
                | CustomCertificateSerialNumberException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException
                | EndEntityProfileValidationException | CertificateSignatureException | NoSuchEndEntityException e) {
            throw new KeyStoreGeneralRaException(e);
        }
        if (endEntity.getTokenType() == EndEntityConstants.TOKEN_SOFT_PEM){
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                outputStream.write(KeyTools.getSinglePemFromKeyStore(keyStore, endEntity.getPassword().toCharArray()));
                return outputStream.toByteArray();
            } catch (IOException | CertificateEncodingException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        } else {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                keyStore.store(outputStream, endEntity.getPassword().toCharArray());
                return outputStream.toByteArray();
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        }
        return null;
    }

    private boolean isNotAfterInclusive(final AuthenticationToken authenticationToken, final EndEntityInformation endEntity) throws AuthorizationDeniedException {
        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, endEntity.getCAId());
        if (caInfo == null) {
            log.warn("CA "+ endEntity.getCAId() + " was not found. Username: " + endEntity.getUsername());
            return true; // Assume X.509
        }
        return caInfo.isExpirationInclusive();
    }

    @Override
    public byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException {
        if(endEntityInformation.getExtendedInformation() == null || endEntityInformation.getExtendedInformation().getCertificateRequest() == null){
            throw new IllegalArgumentException("Could not find CSR for end entity with username " + endEntityInformation.getUsername() + " CSR must be set under endEntityInformation.extendedInformation.certificateRequest");
        }

        RequestMessage req;
        boolean isSshEnroll = endEntityInformation.isSshEndEntity();
        if(!isSshEnroll) {
            // default
            req = RequestMessageUtils.parseRequestMessage(endEntityInformation.getExtendedInformation().getCertificateRequest());
        } else {
            // SSH certificate enrollment
            req = new SshRequestMessage(
                    endEntityInformation.getExtendedInformation().getCertificateRequest(), 
                            endEntityInformation.getDN(), endEntityInformation.getSubjectAltName(),
                            endEntityInformation.getExtendedInformation());
        }
        req.setUsername(endEntityInformation.getUsername());
        req.setPassword(endEntityInformation.getPassword());
        final String encodedValidity = endEntityInformation.getExtendedInformation().getCertificateEndTime();
        req.setRequestValidityNotAfter(encodedValidity == null ? null :
            ValidityDate.getDate(encodedValidity, new Date(), isNotAfterInclusive(authenticationToken, endEntityInformation)));
        try {
            ResponseMessage resp = null;
            if(isSshEnroll) {
                resp = signSessionLocal.createCertificate(authenticationToken, req, SshResponseMessage.class, null);
                if(resp.getFailInfo()!=null) {
                    throw new EjbcaException(ErrorCode.BAD_REQUEST, resp.getFailText());
                }
                return resp.getResponseMessage();
            } else {
                // default
                resp = signSessionLocal.createCertificate(authenticationToken, req, X509ResponseMessage.class, null);
            }
            Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
            return cert.getEncoded();
        } catch (NoSuchEndEntityException | CustomCertificateSerialNumberException | CryptoTokenOfflineException | IllegalKeyException
                | CADoesntExistsException | SignRequestException | SignRequestSignatureException | IllegalNameException | CertificateCreateException
                | CertificateRevokeException | CertificateSerialNumberException | IllegalValidityException | CAOfflineException
                | InvalidAlgorithmException | CertificateExtensionException e) {
            throw new EjbcaException(e);
        } catch (CertificateParsingException | CertificateEncodingException e) {
            throw new IllegalStateException("Internal error with creating Certificate from CertificateResponseMessage");
        }
    }


    @Override
    public byte[] createCertificateRest(final AuthenticationToken authenticationToken, EnrollPkcs10CertificateRequest enrollCertificateRequest)
            throws CertificateProfileDoesNotExistException, CADoesntExistsException, AuthorizationDeniedException,
            EjbcaException, EndEntityProfileValidationException {

        EndEntityInformation endEntityInformation = ejbcaRestHelperSession.convertToEndEntityInformation(authenticationToken, enrollCertificateRequest);
        try {
            return certificateRequestSession.processCertReq(authenticationToken,
                    endEntityInformation,
                    enrollCertificateRequest.getCertificateRequest(),
                    CertificateHelper.CERT_REQ_TYPE_PKCS10,
                    CertificateConstants.CERT_RES_TYPE_CERTIFICATE);
        } catch (NotFoundException e) {
            log.debug("EJBCA REST exception", e);
            throw e; // NFE extends EjbcaException
        } catch (InvalidKeyException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.INVALID_KEY, e.getMessage());
        } catch (IllegalKeyException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.ILLEGAL_KEY, e.getMessage());
        } catch (AuthStatusException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, e.getMessage());
        } catch (AuthLoginException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.LOGIN_ERROR, e.getMessage());
        } catch (SignatureException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.SIGNATURE_ERROR, e.getMessage());
        } catch (SignRequestSignatureException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(e.getMessage());
        } catch (InvalidKeySpecException e) {
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.INVALID_KEY_SPEC, e.getMessage());
        } catch (CesecoreException e) {
            log.debug("EJBCA REST exception", e);
            // Will convert the CESecore exception to an EJBCA exception with the same error code
            throw new EjbcaException(e.getErrorCode(), e);
        } catch (CertificateExtensionException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException | IOException | RuntimeException e) {  // EJBException, ClassCastException, ...
            log.debug("EJBCA REST exception", e);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }


    @Override
    public byte[] createCertificateWS(final AuthenticationToken authenticationToken, final UserDataVOWS userData, final String requestData, final int requestType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, EjbcaException,
            EndEntityProfileValidationException {
        try {
            // Some of the session beans are only needed for authentication or certificate operations, and are passed as null
            final EndEntityInformation endEntityInformation = ejbcaWSHelperSession.convertUserDataVOWS(authenticationToken, userData);
            int responseTypeInt = CertificateConstants.CERT_RES_TYPE_CERTIFICATE;
            if (!responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_CERTIFICATE)) {
                if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7)) {
                    responseTypeInt = CertificateConstants.CERT_RES_TYPE_PKCS7;
                }
                else if (responseType.equalsIgnoreCase(CertificateHelper.RESPONSETYPE_PKCS7WITHCHAIN)) {
                    responseTypeInt = CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN;
                }
                else{
                    throw new NoSuchAlgorithmException("Bad responseType:" + responseType);
                }
            }
            return certificateRequestSession.processCertReq(authenticationToken, endEntityInformation, requestData, requestType, responseTypeInt);
        } catch (NotFoundException e) {
            log.debug("EJBCA WebService error", e);
            throw e; // NFE extends EjbcaException
        } catch (InvalidKeyException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INVALID_KEY, e.getMessage());
        } catch (IllegalKeyException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.ILLEGAL_KEY, e.getMessage());
        } catch (AuthStatusException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, e.getMessage());
        } catch (AuthLoginException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.LOGIN_ERROR, e.getMessage());
        } catch (SignatureException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.SIGNATURE_ERROR, e.getMessage());
        } catch (SignRequestSignatureException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(e.getMessage());
        } catch (InvalidKeySpecException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INVALID_KEY_SPEC, e.getMessage());
        } catch (CesecoreException e) {
            log.debug("EJBCA WebService error", e);
            // Will convert the CESecore exception to an EJBCA exception with the same error code
            throw new EjbcaException(e.getErrorCode(), e);
        } catch (CertificateExtensionException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException | IOException | RuntimeException e) {  // EJBException, ClassCastException, ...
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }

    @Override
    public byte[] softTokenRequest(AuthenticationToken authenticationToken, UserDataVOWS userdata, String keyspec, String keyalg, boolean createJKS) 
            throws AuthorizationDeniedException, CADoesntExistsException, EndEntityProfileValidationException, EjbcaException {
        try {
            // Some of the session beans are only needed for authentication or certificate operations, and are passed as null
            final EndEntityInformation endEntityInformation = ejbcaWSHelperSession.convertUserDataVOWS(authenticationToken, userdata);
            if (endEntityInformation.getExtendedInformation() == null) {
                endEntityInformation.setExtendedInformation(new ExtendedInformation());
            }
            endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmSubType(keyspec);
            endEntityInformation.getExtendedInformation().setKeyStoreAlgorithmType(keyalg);
            return certificateRequestSession.processSoftTokenReq(authenticationToken, endEntityInformation, keyspec, keyalg, createJKS);
        } catch (NotFoundException e) {
            log.debug("EJBCA WebService error", e);
            throw e; // NFE extends EjbcaException
        } catch (AuthStatusException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, e.getMessage());
        } catch (AuthLoginException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.LOGIN_ERROR, e.getMessage());
        } catch (InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INVALID_KEY_SPEC, e.getMessage());
        } catch (CesecoreException e) {
            log.debug("EJBCA WebService error", e);
            // Will convert the CESecore exception to an EJBCA exception with the same error code
            throw new EjbcaException(e.getErrorCode(), e);
        } catch (KeyStoreException| NoSuchAlgorithmException | CertificateException |  RuntimeException e) {  // EJBException, ClassCastException, ...
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }
    
    @Override
    public byte[] enrollAndIssueSshCertificate(final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation,
            final SshRequestMessage sshRequestMessage)
            throws AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException {
        try {
            endEntityInformation.setSshEndEntity(true);
            SshResponseMessage sshResponseMessage = (SshResponseMessage) certificateRequestSession.processCertReq(authenticationToken,
                    endEntityInformation, sshRequestMessage, SshResponseMessage.class);
            return sshResponseMessage.getResponseMessage();
        } catch (NotFoundException e) {
            log.debug("EJBCA SSH enrollment error", e);
            throw e; // NFE extends EjbcaException
        } catch (IllegalKeyException e) {
            log.debug("EJBCA SSH enrollment error", e);
            throw new EjbcaException(ErrorCode.ILLEGAL_KEY, e.getMessage(), e);
        } catch (AuthStatusException e) {
            log.debug("EJBCA SSH enrollment error", e);
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, e.getMessage(), e);
        } catch (AuthLoginException e) {
            log.debug("EJBCA SSH enrollment error", e);
            throw new EjbcaException(ErrorCode.LOGIN_ERROR, e.getMessage(), e);
        } catch (SignRequestSignatureException e) {
            log.debug("EJBCA SSH enrollment error", e);
            throw new EjbcaException(e.getMessage());
        } catch (CesecoreException e) {
            log.debug("EJBCA SSH enrollment error", e);
            // Will convert the CESecore exception to an EJBCA exception with the same error code
            throw new EjbcaException(e.getErrorCode(), e);
        } catch (CertificateExtensionException | RuntimeException e) { // EJBException, ClassCastException, ...
            log.debug("EJBCA SSH enrollment error", e);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    @Override
    public byte[] enrollAndIssueSshCertificateWs(final AuthenticationToken authenticationToken, final UserDataVOWS userDataVOWS,
            final SshRequestMessage sshRequestMessage)
            throws AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException {
        try {
            // Some of the session beans are only needed for authentication or certificate operations, and are passed as null
            final EndEntityInformation endEntityInformation = ejbcaWSHelperSession.convertUserDataVOWS(authenticationToken, userDataVOWS);
            endEntityInformation.setSshEndEntity(true);
            SshResponseMessage sshResponseMessage = (SshResponseMessage) certificateRequestSession.processCertReq(authenticationToken,
                    endEntityInformation, sshRequestMessage, SshResponseMessage.class);
            return sshResponseMessage.getResponseMessage();
        } catch (NotFoundException e) {
            log.debug("EJBCA WebService error", e);
            throw e; // NFE extends EjbcaException
        } catch (IllegalKeyException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.ILLEGAL_KEY, e.getMessage(), e);
        } catch (AuthStatusException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.USER_WRONG_STATUS, e.getMessage(), e);
        } catch (AuthLoginException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.LOGIN_ERROR, e.getMessage(), e);
        } catch (SignRequestSignatureException e) {
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(e.getMessage());
        } catch (CesecoreException e) {
            log.debug("EJBCA WebService error", e);
            // Will convert the CESecore exception to an EJBCA exception with the same error code
            throw new EjbcaException(e.getErrorCode(), e);
        } catch (CertificateExtensionException | RuntimeException e) { // EJBException, ClassCastException, ...
            log.debug("EJBCA WebService error", e);
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    @Override
    public List<CertificateWrapper> getLastCertChain(final AuthenticationToken authenticationToken, final String username) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCertChain: "+username);
        }
        final List<CertificateWrapper> retValues = new ArrayList<>();
        if (endEntityAccessSession.findUser(authenticationToken, username) != null) { // checks authorization on CA and profiles and view_end_entity
            Collection<CertificateWrapper> certs = certificateStoreSession.findCertificatesByUsername(username);
            if (certs.size() > 0) {
                // The latest certificate will be first
                CertificateWrapper firstCert = certs.iterator().next();
                Certificate lastCert;
                if (firstCert != null) {
                    retValues.add(firstCert);
                    lastCert = firstCert.getCertificate();
                    if (log.isDebugEnabled()) {
                        log.debug("Found certificate for user with subjectDN: "+CertTools.getSubjectDN(lastCert)+" and serialNo: "+CertTools.getSerialNumberAsString(lastCert));
                    }
                    // If we added a certificate, we will also append the CA certificate chain
                    appendCaChain(retValues, lastCert);

                } else {
                    log.debug("Found no certificate (in non null list??) for user "+username);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getLastCertChain: "+username);
        }
        return retValues;
    }

    private void appendCaChain(List<CertificateWrapper> certificateList, Certificate certificate) {
        boolean selfSigned = false;
        int iteration = 0; // to control so we don't enter an infinite loop. Max chain length is 10
        while (!selfSigned && iteration < 10) {
            iteration++;
            final String issuerDN = CertTools.getIssuerDN(certificate);
            final Collection<Certificate> caCerts = certificateStoreSession.findCertificatesBySubject(issuerDN);
            if (CollectionUtils.isEmpty(caCerts)) {
                log.info("No certificate found for CA with subjectDN: "+issuerDN);
                break;
            }
            for (final Certificate cert : caCerts) {
                try {
                    certificate.verify(cert.getPublicKey());
                    // this was the right certificate
                    certificateList.add(EJBTools.wrap(cert));
                    // To determine if we have found the last certificate or not
                    selfSigned = CertTools.isSelfSigned(cert);
                    // Find the next certificate in the chain now
                    certificate = cert;
                    break; // Break of iteration over this CAs certs
                } catch (Exception e) {
                    log.debug("Failed verification when looking for CA certificate, this was not the correct CA certificate. IssuerDN: "+issuerDN+", serno: "+CertTools.getSerialNumberAsString(cert));
                }
            }
        }
    }

    @Override
    public boolean markForRecovery(AuthenticationToken authenticationToken, String username, String newPassword, CertificateWrapper cert, boolean localKeyGeneration) throws AuthorizationDeniedException, ApprovalException,
                                    CADoesntExistsException, WaitingForApprovalException, NoSuchEndEntityException, EndEntityProfileValidationException {
        boolean keyRecoverySuccessful;
        boolean authorized = true;
        // If called from the wrong instance, return to proxybean and try next implementation
        final EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, username);
        if (endEntityInformation == null) {
            return false;
        }
        int endEntityProfileId = endEntityInformation.getEndEntityProfileId();
        if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableEndEntityProfileLimitations()) {
            authorized = authorizationSession.isAuthorized(
                    authenticationToken,
                    AccessRulesConstants.ENDENTITYPROFILEPREFIX + endEntityProfileId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                    AccessRulesConstants.REGULAR_RAFUNCTIONALITY + AccessRulesConstants.KEYRECOVERY_RIGHTS
            );
        }
        if (authorized) {
            try {
                if (!localKeyGeneration) {
                    keyRecoverySuccessful = endEntityManagementSession.prepareForKeyRecovery(authenticationToken, username, endEntityProfileId, cert.getCertificate());
                } else {
                    // In this case, the users status is set to 'Key Recovery' but not the flag in KeyRecoveryData since
                    // this is stored in another instance database
                    keyRecoverySuccessful = endEntityManagementSession.prepareForKeyRecoveryInternal(authenticationToken, username, endEntityProfileId, cert.getCertificate());
                }
                if (keyRecoverySuccessful && newPassword != null) {
                    // No approval required, continue by setting a new enrollment code
                    endEntityManagementSession.setPassword(authenticationToken, username, newPassword);
                }
            } catch (WaitingForApprovalException e) {
                // Set new EE password anyway
                if (newPassword != null) { // Password may null if there is a call from EjbcaWS
                    endEntityManagementSession.setPassword(authenticationToken, username, newPassword);
                }
                throw e;
            }
            return keyRecoverySuccessful;
        }
        return false;
    }

    @Override
    public boolean editUser(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation, boolean isClearPwd, String newUsername)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException {
        if (endEntityAccessSession.findUser(authenticationToken, endEntityInformation.getUsername()) == null) {
            // If called from the wrong instance, return to proxybean and try next implementation
            return false;
        } else {
            // only for REST to avoid fetching end entity profile contents to RA
            if(endEntityInformation.getExtendedInformation()!=null && 
                    endEntityInformation.getExtendedInformation().getCustomData(ExtendedInformation.MARKER_FROM_REST_RESOURCE)!=null) {
                EndEntityProfile endEntityProfile = 
                        endEntityProfileSession.getEndEntityProfileNoClone(endEntityInformation.getEndEntityProfileId());
                isClearPwd = endEntityProfile.isClearTextPasswordUsed() && endEntityProfile.isClearTextPasswordDefault();
                endEntityInformation.getExtendedInformation().getRawData().remove(
                        ExtendedInformation.CUSTOMDATA + ExtendedInformation.MARKER_FROM_REST_RESOURCE);
            }
            if (newUsername == null)
                endEntityManagementSession.changeUser(authenticationToken, endEntityInformation, isClearPwd);
            else
                endEntityManagementSession.changeUser(authenticationToken, endEntityInformation, isClearPwd, newUsername);
            return true;
        }
    }

    @Override
    public boolean editUserWs(AuthenticationToken authenticationToken, UserDataVOWS userDataVOWS)
            throws AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, EjbcaException {
        return editUser(authenticationToken, ejbcaWSHelperSession.convertUserDataVOWS(authenticationToken, userDataVOWS), userDataVOWS.isClearPwd(), null);
    }

    @Override
    public List<UserDataVOWS> findUserWS(AuthenticationToken authenticationToken, UserMatch usermatch, int maxNumberOfRows)
            throws AuthorizationDeniedException, IllegalQueryException, EjbcaException {
        List<UserDataVOWS> retValue = null;
        try {
            final org.ejbca.util.query.Query query = ejbcaWSHelperSession.convertUserMatch(authenticationToken, usermatch);
            if (query.getQueryString().contains("subjectDN") || query.getQueryString().contains("serialNo")) {
                Collection<EndEntityInformation> resultsWithCasFiltered = filterCas(authenticationToken, query, maxNumberOfRows);
                GlobalConfiguration globalconfiguration = (GlobalConfiguration) globalConfigurationSession
                        .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                    Collection<EndEntityInformation> resultsWithCasAndEepFiltered = filterEep(authenticationToken, resultsWithCasFiltered);
                    if (CollectionUtils.isNotEmpty(resultsWithCasAndEepFiltered)) {
                        retValue = new ArrayList<>(resultsWithCasAndEepFiltered.size());
                        for (final EndEntityInformation userData : resultsWithCasAndEepFiltered) {
                            retValue.add(ejbcaWSHelperSession.convertEndEntityInformation(userData));
                        }
                    }
                } else {
                    if (CollectionUtils.isNotEmpty(resultsWithCasFiltered)) {
                        retValue = new ArrayList<>(resultsWithCasFiltered.size());
                        for (final EndEntityInformation userData : resultsWithCasFiltered) {
                            retValue.add(ejbcaWSHelperSession.convertEndEntityInformation(userData));
                        }
                    }
                }
            } else {
                Collection<EndEntityInformation> results;
                results = endEntityAccessSession.query(authenticationToken, query, null, null, maxNumberOfRows, AccessRulesConstants.VIEW_END_ENTITY); // also checks authorization
                if (CollectionUtils.isNotEmpty(results)) {
                    retValue = new ArrayList<>(results.size());
                    for (final EndEntityInformation userData : results) {
                        retValue.add(ejbcaWSHelperSession.convertEndEntityInformation(userData));
                    }
                }
            }
        } catch (CesecoreException e) {
            // Convert cesecore exception to EjbcaException
            throw new EjbcaException(e.getErrorCode(), e);
        }
        return retValue;
    }

    private Collection<EndEntityInformation> filterEep(final AuthenticationToken authenticationToken,
            final Collection<EndEntityInformation> resultsWithCasFiltered) {
        final List<Integer> profileIds = new ArrayList<>(
                endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        // Additionally require view access to all the profiles
        for (final Integer profileid : new ArrayList<>(profileIds)) {
            if (!isAuthorizedNoLogging(authenticationToken,
                    AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.VIEW_END_ENTITY)) {
                profileIds.remove(profileid);
            }
        }

        return resultsWithCasFiltered.stream()
                .filter(ee -> endEntityProfileSession.isAuthorizedToView(authenticationToken, ee.getEndEntityProfileId()))
                .collect(Collectors.toList());
    }

    private Collection<EndEntityInformation> filterCas(final AuthenticationToken authenticationToken, final org.ejbca.util.query.Query query, int maxNumberOfRows)
            throws IllegalQueryException {
        log.debug("Query contains subjectDN and/or serialNo, hence using the optimized query!");
        Collection<EndEntityInformation> results = endEntityAccessSession.queryOptimized(authenticationToken, query, maxNumberOfRows,
                AccessRulesConstants.VIEW_END_ENTITY); // also checks authorization
        return results.stream().filter(ee -> caSession.authorizedToCANoLogging(authenticationToken, ee.getCAId())).collect(Collectors.toList());
    }

    @Override
    public int getPublisherQueueLength(AuthenticationToken authenticationToken, String name) throws PublisherDoesntExistsException {
        final int id = publisherSession.getPublisherId(name);
        if (id == 0) {
            throw new PublisherDoesntExistsException("Publisher does not exist: " + name);
        }
        return publisherQueueSession.getPendingEntriesCountForPublisher(id);
    }

    @Override
    public boolean keyRecoveryPossible(final AuthenticationToken authenticationToken, Certificate cert, String username) {
        boolean returnValue = isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY);
        if (((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableEndEntityProfileLimitations()) {
            try {
                EndEntityInformation data = endEntityAccessSession.findUser(authenticationToken, username);
                if (data != null) {
                    int profileId = data.getEndEntityProfileId();
                    returnValue = endEntityAuthorization(authenticationToken, profileId);
                } else {
                    returnValue = false;
                }
            } catch (AuthorizationDeniedException e) {
                log.debug("Administrator: " + authenticationToken + " was not authorized to perform key recovery for end entity: " + username);
                return false;
            }
        }
        return returnValue && keyRecoverySessionLocal.existsKeys(EJBTools.wrap(cert)) && !keyRecoverySessionLocal.isUserMarked(username);
    }

    @Override
    public void keyRecoverWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN)
            throws EjbcaException, AuthorizationDeniedException, WaitingForApprovalException, CADoesntExistsException {
        try {
            final boolean useKeyRecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            if (!useKeyRecovery) {
                throw new EjbcaException(ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, "Keyrecovery must be enabled in the system configuration in order to execute this command.");

            }
            final EndEntityInformation userData = endEntityAccessSession.findUser(authenticationToken, username);
            if (userData == null) {
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
                final String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);
                throw new NotFoundException(msg);
            }
            if (keyRecoverySessionLocal.isUserMarked(username)) {
                // User is already marked for recovery.
                return;
            }
            // check CAID
            final int caId = userData.getCAId();
            caSession.verifyExistenceOfCA(caId);
            if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId)) {
                final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caId, null);
                throw new AuthorizationDeniedException(msg);
            }

            // find certificate to recover
            final Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(issuerDN, new BigInteger(certSNinHex,16));
            if (cert == null) {
                final String msg = intres.getLocalizedMessage("ra.errorfindentitycert", issuerDN, certSNinHex);
                throw new NotFoundException(msg);
            }

            // Do the work, mark user for key recovery
            if (!endEntityManagementSession.prepareForKeyRecovery(authenticationToken, userData.getUsername(), userData.getEndEntityProfileId(), cert)) {
                // Reset user status and throw exception
                endEntityManagementSession.setUserStatus(authenticationToken, username, userData.getStatus());
                throw new EjbcaException(ErrorCode.KEY_RECOVERY_NOT_AVAILABLE, "Key recovery data not found for user '" + username + "'");
            }
        } catch (NotFoundException e) {
            log.debug("EJBCA WebService error", e);
            throw e; // extends EjbcaException
        } catch (NoSuchEndEntityException e) {
            throw new NotFoundException(intres.getLocalizedMessage("ra.errorentitynotexist", username));
        }
    }

    @Override
    public byte[] keyRecoverEnrollWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN, String password, String hardTokenSN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException, WaitingForApprovalException {
        keyRecoverWS(authenticationToken, username, certSNinHex, issuerDN);
        EndEntityInformation userData = endEntityAccessSession.findUser(authenticationToken, username);
        userData.setPassword(password);
        byte[] keyStoreBytes = generateKeyStore(authenticationToken, userData);

        // Lots of checks. Can't know what WS client sends in.
        if (!StringUtils.isEmpty(hardTokenSN) && !hardTokenSN.equals("NONE") && !hardTokenSN.equals("null")) {
            final KeyStore keyStore;
            try {
                if (userData.getTokenType() == EndEntityConstants.TOKEN_SOFT_P12) {
                    keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
                } else {
                    keyStore = KeyStore.getInstance("JKS");
                }
                keyStore.load(new ByteArrayInputStream(keyStoreBytes), password.toCharArray());
                final Enumeration<String> en = keyStore.aliases();
                final String alias = en.nextElement();
                keyStore.getCertificate(alias);
            } catch (CertificateException e) {
                throw new EjbcaException(ErrorCode.CERT_COULD_NOT_BE_PARSED, e.getMessage());
            } catch (NoSuchAlgorithmException | IOException | KeyStoreException | NoSuchProviderException e) {
                throw new EjbcaException(ErrorCode.NOT_SUPPORTED_KEY_STORE, e.getMessage());
            }
        }
        return keyStoreBytes;
    }

    /** Help function used to check end entity profile authorization. */
    private boolean endEntityAuthorization(AuthenticationToken admin, int profileId) {
        return isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileId
                    + AccessRulesConstants.KEYRECOVERY_RIGHTS, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + AccessRulesConstants.KEYRECOVERY_RIGHTS);
    }

    @Override
    public boolean changeCertificateStatus(final AuthenticationToken authenticationToken, final String fingerprint, final int newStatus, final int newRevocationReason)
            throws ApprovalException, WaitingForApprovalException {
        final CertificateDataWrapper cdw = searchForCertificate(authenticationToken, fingerprint);
        if (cdw!=null) {
            final BigInteger serialNumber = new BigInteger(cdw.getCertificateData().getSerialNumber());
            final String issuerDn = cdw.getCertificateData().getIssuerDN();
            try {
                // This call checks CA authorization, EEP authorization (if enabled) and /ra_functionality/revoke_end_entity
                endEntityManagementSession.revokeCert(authenticationToken, serialNumber, issuerDn, newRevocationReason);
                return true;
            } catch (AlreadyRevokedException e) {
                // If it is already revoked, great! The client got what the client wanted.. (almost at least, since reason might differ)
                log.info("Client '"+authenticationToken+"' requested status change of when status was already set for certificate '"+fingerprint+"'. Considering operation successful.");
                return true;
            } catch (AuthorizationDeniedException e) {
                log.info("Client '"+authenticationToken+"' requested status change of certificate '"+fingerprint+"' but is not authorized to revoke certificates.");
            } catch (NoSuchEndEntityException e) {
                // The certificate did exist a few lines ago, but must have been removed since then. Treat this like it never existed
                log.info("Client '"+authenticationToken+"' requested status change of certificate '"+fingerprint+"' that does not exist.");
            }
        } else {
            log.info("Client '"+authenticationToken+"' requested status change of certificate '"+fingerprint+"' that does not exist or the client is not authorized to see.");
        }
        return false;
    }

    @Override
    public void revokeCert(AuthenticationToken authenticationToken, BigInteger certSerNo, Date revocationDate, Date invalidityDate, String issuerDn, int reason, boolean checkDate)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException {
        // First check if we handle the CA, to fail-fast, and reflect the functionality of remote API (WS)
        final int caId = CertTools.stringToBCDNString(issuerDn).hashCode();
        caSession.verifyExistenceOfCA(caId);
        endEntityManagementSession.revokeCert(authenticationToken, certSerNo, revocationDate, issuerDn, reason, checkDate);
    }

    @Override
    public void revokeAndDeleteUser(final AuthenticationToken authenticationToken, final String username, final int reason)
        throws AuthorizationDeniedException, NoSuchEndEntityException, WaitingForApprovalException, CouldNotRemoveEndEntityException, ApprovalException {
        endEntityManagementSession.revokeAndDeleteUser(authenticationToken, username, reason);
    }

    @Override
    public void revokeCertWithMetadata(AuthenticationToken authenticationToken, CertRevocationDto certRevocationDto)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException, IllegalArgumentException, CertificateProfileDoesNotExistException {
        // First check if we handle the CA, to fail-fast, and reflect the functionality of remote API (WS)

        final int caId = CertTools.stringToBCDNString(certRevocationDto.getIssuerDN()).hashCode();
        caSession.verifyExistenceOfCA(caId);
        endEntityManagementSession.revokeCertWithMetadata(authenticationToken, certRevocationDto);
    }

    @Override
    public void revokeUser(final AuthenticationToken authenticationToken, final String username, final int reason, final boolean deleteUser) throws AuthorizationDeniedException, CADoesntExistsException,
        WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException, EjbcaException {
        endEntityManagementSession.revokeUser(authenticationToken, username, reason, deleteUser);
    }

    @Override
    public CertificateStatus getCertificateStatus(AuthenticationToken authenticationToken, String issuerDn, BigInteger serNo) throws CADoesntExistsException, AuthorizationDeniedException {
        // First check if we handle the CA, to fail-fast, and reflect the functionality of remote API (WS)
        final int caId = CertTools.stringToBCDNString(issuerDn).hashCode();
        caSession.verifyExistenceOfCA(caId);
        // Check if we are authorized to this CA
        if(!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() +caId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() +caId, null);
            throw new AuthorizationDeniedException(msg);
        }

        return noConflictCertificateStoreSession.getStatus(issuerDn, serNo);
    }

    private GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
        return (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    }

    @Override
    public ApprovalProfile getApprovalProfileForAction(final AuthenticationToken authenticationToken, final ApprovalRequestType action, final int caId, final int certificateProfileId) throws AuthorizationDeniedException{
        KeyToValueHolder<CAInfo> caInfoHolder = getAuthorizedCAInfos(authenticationToken).get(caId);
        KeyToValueHolder<CertificateProfile> certificateProfileHolder = getAllAuthorizedCertificateProfiles(authenticationToken).get(certificateProfileId);
        if(caInfoHolder == null){
            throw new AuthorizationDeniedException("Could not get approval profile because " + authenticationToken + " doesn't have access to CA with ID = " + caId);
        }
        if(certificateProfileHolder == null){
            throw new AuthorizationDeniedException("Could not get approval profile because " + authenticationToken + " doesn't have access to certificate profile with ID = " + certificateProfileId);
        }
        return approvalProfileSession.getApprovalProfileForAction(action, caInfoHolder.getValue(), certificateProfileHolder.getValue());
    }
    
    @Override
    public Integer createApprovalRequest(final AuthenticationToken authenticationToken, final int type, final int approvalProfileId, final int endEntityProfileId, final String acmeAccountId) throws AuthorizationDeniedException, ApprovalException {
        return approvalSession.createApprovalRequest(authenticationToken, type, approvalProfileId, endEntityProfileId, acmeAccountId);
    }

    @Override
    public byte[] scepDispatch(final AuthenticationToken authenticationToken, final String operation, final String message, final String scepConfigurationAlias)
            throws NoSuchAliasException, CADoesntExistsException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException,
            CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            SignatureException, CertificateException, AuthorizationDeniedException, CertificateExtensionException, CertificateRenewalException {
        return scepMessageDispatcherSession.dispatchRequest(authenticationToken, operation, message, scepConfigurationAlias);
    }
    
    @Override
    public byte[] verifyScepPkcs10RequestMessage(AuthenticationToken authenticationToken, String alias, byte[] message) throws CertificateCreateException {
        return scepMessageDispatcherSession.verifyRequestMessage(authenticationToken, alias, message);
    }

    @Override
    public byte[] cmpDispatch(final AuthenticationToken authenticationToken, final byte[] pkiMessageBytes, final String cmpConfigurationAlias) throws NoSuchAliasException {
        return cmpMessageDispatcherSession.dispatchRequest(authenticationToken, pkiMessageBytes, cmpConfigurationAlias);
    }

    @Override
    public byte[] estDispatch(String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException {
        // throws UnsupportedOperationException if EST is not available (Community);
        if (!WebConfiguration.isLegacyEstRaApiAllowed()) { // default is off
            log.info("RA tried to use legacy RA API call for EST, which is disabled by default for security reasons. Please upgrade the RA, or set raapi.legacyest.enabled=true in web.properties to allow this.");
            throw new NoSuchAliasException("CA configuration does not allow RA to use legacy API for EST."); // No better exception. We can't change an existing API.
        }
        try {
            return estOperationsSessionLocal.dispatchRequest(new AlwaysAllowLocalAuthenticationToken("EST - Call using legacy RA API call"), operation, alias, cert, username, password, requestBody);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Should not get AuthorizationDeniedException with AlwaysAllowLocalAuthenticationToken");
        }
    }

    @Override
    public byte[] estDispatchAuthenticated(final AuthenticationToken authenticationToken, String operation, String alias, X509Certificate cert, String username, String password, byte[] requestBody)
            throws NoSuchAliasException, CADoesntExistsException, CertificateCreateException, CertificateRenewalException, AuthenticationFailedException, AuthorizationDeniedException {
        // throws UnsupportedOperationException if EST is not available (Community);
        return estOperationsSessionLocal.dispatchRequest(authenticationToken, operation, alias, cert, username, password, requestBody);
    }

    @Override
    public Collection<CertificateWrapper> getCertificateChain(final AuthenticationToken authenticationToken, int caId) throws AuthorizationDeniedException, CADoesntExistsException {
        if(!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caId, null);
            throw new AuthorizationDeniedException(msg);
        }
        CAInfo caInfo = caSession.getCAInfoInternal(caId);
        if(caInfo == null) {
            throw new CADoesntExistsException("CA with ID " + caId + " doesn't exist");
        }
        return EJBTools.wrapCertCollection(caInfo.getCertificateChain());
    }

    private Date getDate(long days) {
        Date findDate = new Date();
        long millis = (days * 24 * 60 * 60 * 1000);
        findDate.setTime(findDate.getTime() + millis);
        return findDate;
    }

    @Override
    public int getCountOfCertificatesByExpirationTime(final AuthenticationToken authenticationToken, long days) throws AuthorizationDeniedException {
        if(!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate")) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAFUNCTIONALITY.resource()+"/view_certificate", null);
            throw new AuthorizationDeniedException(msg);
        }
        Date findDate = getDate(days);
        return certificateStoreSession.findNumberOfExpiringCertificates(findDate);
    }

    @Override
    public void customLog(final AuthenticationToken authenticationToken, final String type, final String caName, final String username, final String certificateSn,
    		final String msg, final EventType event) throws AuthorizationDeniedException, CADoesntExistsException {
        caAdminSession.customLog(authenticationToken, type, caName, username, certificateSn, msg, event);
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByUsername(final AuthenticationToken authenticationToken, final String username, final boolean onlyValid, final long now)
            throws AuthorizationDeniedException, CertificateEncodingException {
        return endEntityAccessSession.findCertificatesByUsername(authenticationToken, username, onlyValid, now);
    }

    @Override
    public Map<String, Integer> getAvailableCertificateProfiles(final AuthenticationToken authenticationToken, final int entityProfileId)
            throws EndEntityProfileNotFoundException {
        return endEntityProfileSession.getAvailableCertificateProfiles(authenticationToken, entityProfileId);
    }

    @Override
    public Map<String, Integer> getAvailableCasInProfile(final AuthenticationToken authenticationToken, final int entityProfileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
        return endEntityProfileSession.getAvailableCasInProfile(authenticationToken, entityProfileId);
    }

    @Override
    public CertificateWrapper getCertificate(AuthenticationToken authenticationToken, String certSNinHex, String issuerDN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        return endEntityAccessSession.getCertificate(authenticationToken, certSNinHex, issuerDN);
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTime(final AuthenticationToken authenticationToken, final long days,
            final int maxNumberOfResults, final int offset) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate")) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource",
                    StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate", null);
            throw new AuthorizationDeniedException(msg);
        }
        Date findDate = getDate(days);
        return EJBTools.wrapCertCollection(certificateStoreSession.findExpiringCertificates(findDate, maxNumberOfResults, offset));
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTimeAndType(AuthenticationToken authenticationToken, long days, int certificateType, int maxNumberOfResults)
            throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate")) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource",
                    StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate", null);
            throw new AuthorizationDeniedException(msg);
        }
        final Date findDate = new Date();
        final long millis = (days * 24 * 60 * 60 * 1000);
        findDate.setTime(findDate.getTime() + millis);
        final List<Certificate> result = certificateStoreSession.findCertificatesByExpireTimeAndTypeWithLimit(findDate, certificateType, maxNumberOfResults);
        return EJBTools.wrapCertCollection(result);
    }

    @Override
    public Collection<CertificateWrapper> getCertificatesByExpirationTimeAndIssuer(AuthenticationToken authenticationToken, long days, String issuerDN, int maxNumberOfResults)
            throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate")) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource",
                    StandardRules.CAFUNCTIONALITY.resource() + "/view_certificate", null);
            throw new AuthorizationDeniedException(msg);
        }
        final Date findDate = new Date();
        final long millis = (days * 24 * 60 * 60 * 1000);
        findDate.setTime(findDate.getTime() + millis);
        final List<java.security.cert.Certificate> result = certificateStoreSession.findCertificatesByExpireTimeAndIssuerWithLimit(findDate, issuerDN, maxNumberOfResults);
        return EJBTools.wrapCertCollection(result);
    }

    @Override
    public Collection<CertificateWrapper> getLastCaChain(final AuthenticationToken authenticationToken, final String caName)
            throws AuthorizationDeniedException, CADoesntExistsException {
        return caSession.getCaChain(authenticationToken, caName);
    }

    @Override
    public byte[] processCertificateRequest(final AuthenticationToken authenticationToken, final String username, final String password, final String req, final int reqType,
            final String hardTokenSN, final String responseType)
            throws AuthorizationDeniedException, EjbcaException, CesecoreException,
            CertificateExtensionException, InvalidKeyException, SignatureException,
            InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException {
        try {
            return signSessionLocal.createCertificateWS(authenticationToken, username, password, req, reqType, responseType);
        } catch (ParseException | ConstructionException | NoSuchFieldException e) {
            throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
        }
    }

    @Override
    public byte[] getLatestCrl(final AuthenticationToken authenticationToken, final String caName, final boolean deltaCRL)
            throws AuthorizationDeniedException, CADoesntExistsException {
        final CAInfo cainfo = caSession.getCAInfo(authenticationToken, caName);
        if (cainfo == null) {
            throw new CADoesntExistsException("CA with name " + caName + " doesn't exist.");
        }
        // This method is used from the EjbcaWS.getLatestCRL Web Service method, and it does not allow specifying a partition.
        return crlStoreSession.getLastCRL(cainfo.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, deltaCRL);
    }

    @Override
    public byte[] getLatestCrlByRequest(AuthenticationToken authenticationToken, RaCrlSearchRequest request) throws AuthorizationDeniedException, CADoesntExistsException {
        String issuerDn;
        if (StringUtils.isNotEmpty(request.getIssuerDn())) {
            issuerDn = request.getIssuerDn();
        } else {
            final CAInfo cainfo = caSession.getCAInfo(authenticationToken, request.getCaName());
            if (cainfo == null) {
                throw new CADoesntExistsException("CA with name " + request.getCaName() + " doesn't exist.");
            }
            issuerDn = cainfo.getSubjectDN();
        }
        return crlStoreSession.getLastCRL(issuerDn, request.getCrlPartitionIndex(), request.isDeltaCRL());
    }

    @Override
    public byte[] getLatestCrlByIssuerDn(AuthenticationToken authenticationToken, String issuerDn, boolean deltaCRL)
            throws AuthorizationDeniedException, CADoesntExistsException {
        final CAInfo cainfo = caSession.getCAInfo(authenticationToken, issuerDn.hashCode());
        if (cainfo == null) {
            throw new CADoesntExistsException("CA with subjectDn " + issuerDn + " doesn't exist.");
        }
        // This method is used from the EjbcaWS.getLatestCRL Web Service method, and it does not allow specifying a partition.
        return crlStoreSession.getLastCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, deltaCRL);
    }

    @Override
    public Integer getRemainingNumberOfApprovals(final AuthenticationToken authenticationToken, final int requestId)
            throws ApprovalException, ApprovalRequestExpiredException {
        return approvalSession.getRemainingNumberOfApprovals(requestId);
    }

    @Override
    public Integer isApproved(final AuthenticationToken authenticationToken, final int approvalId)
            throws ApprovalException, ApprovalRequestExpiredException {
        return approvalSession.isApproved(approvalId);
    }

    @Override
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String... resource) {
        return authorizationSession.isAuthorized(authenticationToken, resource);
    }

    @Override
    public void republishCertificate(AuthenticationToken authenticationToken, String serialNumberInHex, String issuerDN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        final String bcIssuerDN = CertTools.stringToBCDNString(issuerDN);
        caSession.verifyExistenceOfCA(bcIssuerDN.hashCode());
        final CertReqHistory certReqHistory = certreqHistorySession.retrieveCertReqHistory(new BigInteger(serialNumberInHex,16), bcIssuerDN);
        if(certReqHistory == null){
            throw new PublisherException("Error: the certificate with serialnumber : " + serialNumberInHex +" and issuerdn " + issuerDN + " couldn't be found in database.");
        }
        ejbcaWSHelperSession.isAuthorizedToRepublish(authenticationToken, certReqHistory.getUsername(),bcIssuerDN.hashCode());
        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certReqHistory.getEndEntityInformation().getCertificateProfileId());
        if (certificateProfile != null) {
            if (certificateProfile.getPublisherList().size() > 0) {
                final boolean pubStoreCertificateResult = publisherSession.storeCertificate(
                        authenticationToken, certificateProfile.getPublisherList(), certReqHistory.getFingerprint(),
                        certReqHistory.getEndEntityInformation().getPassword(), certReqHistory.getEndEntityInformation().getCertificateDN(),
                        certReqHistory.getEndEntityInformation().getExtendedInformation());
                if(!pubStoreCertificateResult) {
                    throw new PublisherException("Error: publication failed to at least one of the defined publishers.");
                }
            } else {
                throw new PublisherException("Error no publisher defined for the given certificate.");
            }
        }
        throw new PublisherException("Error : Certificate profile couldn't be found for the given certificate.");
    }

    @Override
    public byte[] generateOrKeyRecoverToken(final AuthenticationToken authenticationToken, final String username, final String password, final String hardTokenSN, final String keySpecification,
            final String keyAlgorithm) throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException {
        return keyStoreCreateSessionLocal.generateOrKeyRecoverTokenAsByteArray(authenticationToken, username, password, keySpecification, keyAlgorithm);
    }

    @Override
    public byte[] getEndEntityProfileAsXml(final AuthenticationToken authenticationToken, final int profileId)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
        return endEntityProfileSession.getProfileAsXml(authenticationToken, profileId);
    }

    @Override
    public byte[] getSshCaPublicKey(String caName) throws SshKeyException, CADoesntExistsException {
        CAInfo caInfo = caSession.getCAInfoInternal(-1, caName, true);
        if(caInfo == null) {
            throw new CADoesntExistsException("CA with name " + caName + " does not exist.");
        }
        if(caInfo.getCAType() != SshCaInfo.CATYPE_SSH) {
            throw new SshKeyException("CA of name " + caName + " is not an SSH CA.");
        } else {
            PublicKey publicKey = caInfo.getCertificateChain().get(0).getPublicKey();
            SshPublicKey sshPublicKey = SshKeyFactory.INSTANCE.getSshPublicKey(publicKey);
            try {
                return sshPublicKey.encodeForExport(caName);
            } catch (IOException e) {
                throw new SshKeyException("Could not encode public key for export.", e);
            }
        }
    }

    @Override
    public byte[] getCertificateProfileAsXml(final AuthenticationToken authenticationToken, final int profileId)
            throws AuthorizationDeniedException, CertificateProfileDoesNotExistException {
        return certificateProfileSession.getProfileAsXml(authenticationToken, profileId);
    }

    @Override
    public Collection<CertificateWrapper> processCardVerifiableCertificateRequest(
            final AuthenticationToken authenticationToken, final String username, final String password, final String cvcReq
    ) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, WaitingForApprovalException,
            CertificateExpiredException, CesecoreException {
        return signSessionLocal.createCardVerifiableCertificateWS(authenticationToken, username, password, cvcReq);
    }

    @Override
    public HashSet<String> getCaaIdentities(final AuthenticationToken authenticationToken, final int caId)
            throws AuthorizationDeniedException, CADoesntExistsException {
        final HashSet<String> caaIdentities = new HashSet<>();
        final CACommon ca = caSession.getCA(authenticationToken, caId);
        if (ca == null) {
            throw new CADoesntExistsException("The CA with id " + caId + " does not exist on peer.");
        }
        for (final int validatorId : ca.getValidators()) {
            final Validator validator = keyValidatorSession.getValidator(validatorId);
            if (validator == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Missing validator ID " + validatorId + " in CA '" + ca.getName() + "'");
                }
                continue;
            }
            if (validator.getValidatorTypeIdentifier().equals(DnsNameValidator.CAA_TYPE_IDENTIFIER)) {
                caaIdentities.addAll(((CaaIdentitiesValidator) validator).getIssuers());
            }
        }
        return caaIdentities;
    }

    @Override
    public AcmeAccount getAcmeAccountById(String accountId) {
        return acmeAccountDataSession.getAcmeAccount(accountId);
    }

    @Override
    public AcmeAccount getAcmeAccountByPublicKeyStorageId(final String publicKeyStorageId) {
        return acmeAccountDataSession.getAcmeAccountByPublicKeyStorageId(publicKeyStorageId);
    }

    @Override
    public String parseAcmeEabMessage(AuthenticationToken authenticationToken, String alias, String requestUrl, String requestJwk,
            String eabRequestJsonString) throws AcmeProblemException {
        return acmeConfigurationSession.parseAcmeEabMessage(authenticationToken, alias, requestUrl, requestJwk, eabRequestJsonString);
    }

    @Override
    public String persistAcmeAccount(final AcmeAccount acmeAccount) {
        return acmeAccountDataSession.createOrUpdate(acmeAccount);
    }

    @Override
    public AcmeOrder getAcmeOrderById(final String orderId) {
        return acmeOrderDataSession.getAcmeOrder(orderId);
    }

    @Override
    public Set<AcmeOrder> getAcmeOrdersByAccountId(String accountId) {
        return acmeOrderDataSession.getAcmeOrdersByAccountId(accountId);
    }

    @Override
    public Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(String fingerprint) {
        return acmeOrderDataSession.getFinalizedAcmeOrdersByFingerprint(fingerprint);
    }

    @Override
    public String persistAcmeOrder(final AcmeOrder acmeOrder) {
        return acmeOrderDataSession.createOrUpdate(acmeOrder);
    }

    @Override
    public List<String> persistAcmeOrders(final List<AcmeOrder> acmeOrders) {
        return acmeOrderDataSession.createOrUpdate(acmeOrders);
    }

    @Override
    public void removeAcmeOrder(String orderId) {
        acmeOrderDataSession.remove(orderId);
    }

    @Override
    public void removeAcmeOrders(List<String> orderIds) {
        acmeOrderDataSession.removeAll(orderIds);
    }

    @Override
    public AcmeAuthorization getAcmeAuthorizationById(String authorizationId) {
        return acmeAuthorizationDataSession.getAcmeAuthorization(authorizationId);
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId) {
        return acmeAuthorizationDataSession.getAcmeAuthorizationsByOrderId(orderId);
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId) {
        return acmeAuthorizationDataSession.getAcmeAuthorizationsByAccountId(accountId);
    }

    @Override
    public List<AcmeAuthorization> getAcmePreAuthorizationsByAccountIdAndIdentifiers(String accountId, List<AcmeIdentifier> identifiers) {
        return acmeAuthorizationDataSession.getAcmePreAuthorizationsByAccountIdAndIdentifiers(accountId, identifiers);
    }

    @Override
    public String persistAcmeAuthorization(AcmeAuthorization acmeAuthorization) {
        return acmeAuthorizationDataSession.createOrUpdate(acmeAuthorization);
    }

    @Override
    public void persistAcmeAuthorizationList(List<AcmeAuthorization> acmeAuthorizations) {
        acmeAuthorizationDataSession.createOrUpdateList(acmeAuthorizations);
    }

    @Override
    public AcmeChallenge getAcmeChallengeById(String challengeId) {
        return acmeChallengeDataSession.getAcmeChallenge(challengeId);
    }

    @Override
    public List<AcmeChallenge> getAcmeChallengesByAuthorizationId(String authorizationId) {
        return acmeChallengeDataSession.getAcmeChallengesByAuthorizationId(authorizationId);
    }

    @Override
    public String persistAcmeChallenge(AcmeChallenge acmeChallenge) {
        return acmeChallengeDataSession.createOrUpdate(acmeChallenge);
    }

    @Override
    public void persistAcmeChallengeList(List<AcmeChallenge> acmeChallenges) {
        acmeChallengeDataSession.createOrUpdateList(acmeChallenges);
    }

    @Override
    public byte[] addUserAndGenerateKeyStore(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean isClearPwd) throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        try {
            endEntity = endEntityManagementSession.addUser(authenticationToken, endEntity, isClearPwd);
        } catch (CesecoreException e) {
            //Wrapping the CesecoreException.errorCode
            throw new EjbcaException(e);
        } catch (EndEntityProfileValidationException e) {
            //Wraps @WebFault Exception based with @NonSensitive EjbcaException based
            throw new EndEntityProfileValidationRaException(e);
        }
        KeyStore keyStore;
        try {
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntity.getEndEntityProfileId());
            boolean useKeyRecovery = ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            EndEntityInformation data = endEntityAccessSession.findUser(endEntity.getUsername());
            if (data == null) {
                throw new EjbcaException(ErrorCode.USER_NOT_FOUND, "User '" + endEntity.getUsername() + "' does not exist");
            }
            final boolean saveKeysFlag = data.getKeyRecoverable() && useKeyRecovery && (data.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
            final boolean loadKeysFlag = (data.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && useKeyRecovery;
            final boolean reuseCertificateFlag = endEntityProfile.getReUseKeyRecoveredCertificate();
            final String encodedValidity = endEntity.getExtendedInformation().getCertificateEndTime();
            final Date notAfter = encodedValidity == null ? null :
                ValidityDate.getDate(encodedValidity, new Date(), isNotAfterInclusive(authenticationToken, endEntity));
            keyStore = keyStoreCreateSessionLocal.generateOrKeyRecoverTokenWithoutViewEndEntityAccessRule(authenticationToken,
                    endEntity.getUsername(), // Username
                    endEntity.getPassword(), // Enrollment code
                    endEntity.getCAId(), // The CA signing the private keys
                    endEntity.getExtendedInformation().getKeyStoreAlgorithmSubType(), // Keylength
                    endEntity.getExtendedInformation().getKeyStoreAlgorithmType(), // Signature algorithm
                    null, // Not valid before
                    notAfter, // Not valid after
                    endEntity.getTokenType(), // Type of token
                    loadKeysFlag, // Perform key recovery?
                    saveKeysFlag, // Save private keys?
                    reuseCertificateFlag, // Reuse recovered cert?
                    endEntity.getEndEntityProfileId()); // Identifier for end entity
        } catch (KeyStoreException | InvalidAlgorithmParameterException | CADoesntExistsException | IllegalKeyException
                | CertificateCreateException | IllegalNameException | CertificateRevokeException | CertificateSerialNumberException
                | CryptoTokenOfflineException | IllegalValidityException | CAOfflineException | InvalidAlgorithmException
                | CustomCertificateSerialNumberException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException
                | EndEntityProfileValidationException | CertificateSignatureException | NoSuchEndEntityException e) {
            cleanupAfterFailure(endEntity);
            throw new KeyStoreGeneralRaException(e);
        }
        if (endEntity.getTokenType() == EndEntityConstants.TOKEN_SOFT_PEM) {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                outputStream.write(KeyTools.getSinglePemFromKeyStore(keyStore, endEntity.getPassword().toCharArray()));
                return outputStream.toByteArray();
            } catch (IOException | CertificateEncodingException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        } else {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                keyStore.store(outputStream, endEntity.getPassword().toCharArray());
                return outputStream.toByteArray();
            } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                log.error(e); //should never happen if keyStore is valid object
            }
        }
        cleanupAfterFailure(endEntity);
        return null;
    }


    @Override
    public byte[] addUserAndCreateCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation, boolean isClearPwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        if(endEntityInformation.getExtendedInformation() == null || endEntityInformation.getExtendedInformation().getCertificateRequest() == null){
            throw new IllegalArgumentException("Could not find CSR for end entity with username " + endEntityInformation.getUsername() + " CSR must be set under endEntityInformation.extendedInformation.certificateRequest");
        }

        try {
            endEntityInformation = endEntityManagementSession.addUser(authenticationToken, endEntityInformation, isClearPwd);
        } catch (CesecoreException e) {
            //Wrapping the CesecoreException.errorCode
            throw new EjbcaException(e);
        } catch (EndEntityProfileValidationException e) {
            //Wraps @WebFault Exception based with @NonSensitive EjbcaException based
            throw new EndEntityProfileValidationRaException(e);
        }
        try {
            final RequestMessage req = RequestMessageUtils.parseRequestMessage(endEntityInformation.getExtendedInformation().getCertificateRequest());
            if (req == null) {
                cleanupAfterFailure(endEntityInformation);
                throw new IllegalStateException("Failed to parse certificate request");
            }
            req.setUsername(endEntityInformation.getUsername());
            req.setPassword(endEntityInformation.getPassword());
            final String encodedValidity = endEntityInformation.getExtendedInformation().getCertificateEndTime();
            req.setRequestValidityNotAfter(encodedValidity == null ? null :
                    ValidityDate.getDate(encodedValidity, new Date(), isNotAfterInclusive(authenticationToken, endEntityInformation)));
            ResponseMessage resp = signSessionLocal.createCertificate(authenticationToken, req, X509ResponseMessage.class, null); // works for CVC also
            if (resp.getStatus() == ResponseStatus.FAILURE) {
                cleanupAfterFailure(endEntityInformation);
                throw new EjbcaException(resp.getFailText());
            }
            Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
            return cert.getEncoded();
        } catch (NoSuchEndEntityException | CustomCertificateSerialNumberException | CryptoTokenOfflineException | IllegalKeyException
                | CADoesntExistsException | SignRequestException | SignRequestSignatureException | IllegalNameException | CertificateCreateException
                | CertificateRevokeException | CertificateSerialNumberException | IllegalValidityException | CAOfflineException
                | InvalidAlgorithmException | CertificateExtensionException e) {
            cleanupAfterFailure(endEntityInformation);
            throw new EjbcaException(e);
        } catch (CertificateParsingException | CertificateEncodingException e) {
            throw new IllegalStateException("Internal error with creating X509Certificate from CertificateResponseMessage", e);
        }
    }

    private void cleanupAfterFailure(final EndEntityInformation endEntityInformation) {
        try {
            // We don't want to roll back certificate enrollment if a post-issuance step failed.
            // So we delete the end-entity only, rather than triggering a rollback.
            //
            // We only delete the end entity here. The createCertificate/generateOrKeyRecoverToken calls
            // are responsible for revocation is the certificate is issued half-way.
            endEntityManagementSession.deleteUser(new AlwaysAllowLocalAuthenticationToken("Failed Enrollment Cleanup"), endEntityInformation.getUsername());
        } catch (NoSuchEndEntityException | AuthorizationDeniedException | CouldNotRemoveEndEntityException | RuntimeException e) {
            // We don't want the admin to focus on this error, so we use lower log levels than normal
            log.info("End entity could not be deleted after issuance failure: " + e.getMessage());
            log.trace("Stack trace from cleanup", e);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends ConfigurationBase> T getGlobalConfiguration(final Class<T> type) {
        T result = null;
        if (GlobalConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        } else if (GlobalCesecoreConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        } else if (GlobalAcmeConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(GlobalAcmeConfiguration.ACME_CONFIGURATION_ID);
        } else if (GlobalOcspConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        } else if (GlobalUpgradeConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        } else if (OAuthConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        } else if (ScepConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        } else if (EABConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(EABConfiguration.EAB_CONFIGURATION_ID);
        } else if (CmpConfiguration.class.getName().equals(type.getName())) {
            result = (T) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        }
        if (log.isDebugEnabled()) {
            if (result != null) {
                log.debug("Found configuration of class '" + type.getName() + "': " + result.getRawData() + ".");
            } else  {
                log.debug("Could not find configuration with class '" + type.getName() + "'. Probably the request was sent from an RA peer of a newer version");
            }
        }
        return result;
    }

    @Override
    public ScepResponseInfo scepDispatchIntune(final AuthenticationToken authenticationToken, final String operation, final String message, final String scepConfigurationAlias)
            throws NoSuchAliasException, CADoesntExistsException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException,
            CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            SignatureException, CertificateException, AuthorizationDeniedException, CertificateExtensionException, CertificateRenewalException {
        return scepMessageDispatcherSession.dispatchRequestIntune(authenticationToken, operation, message, scepConfigurationAlias);
    }

    @Override
    public byte[] doEtsiOperation(AuthenticationToken authenticationToken, String ecaCertificateId, 
                                byte[] requestBody, int operationCode) throws AuthorizationDeniedException, EjbcaException {
        log.info("requestBody: " + Hex.toHexString(requestBody));
        return ecaOperationsSession.doEtsiOperation(authenticationToken, ecaCertificateId, requestBody, operationCode);
    }

    @Override
    public RaCertificateDataOnRenew getCertificateDataForRenew(BigInteger serno, String issuerDn) {
        String username = certificateStoreSession.findUsernameByCertSerno(serno, issuerDn);
        if (username != null) {
            RaCertificateDataOnRenew result = new RaCertificateDataOnRenew();
            result.setUsername(username);
            boolean isRevoked = certificateStoreSession.isRevoked(issuerDn, serno);
            result.setRevoked(isRevoked);
            if (!isRevoked) {
                UserData userData = endEntityAccessSession.findByUsername(username);
                Map<Integer, String> endEntityProfileIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
                final Map<Integer, String> certificateProfileIdToNameMap = certificateProfileSession.getCertificateProfileIdToNameMap();
                result.setEndEntityProfileName(endEntityProfileIdToNameMap.get(userData.getEndEntityProfileId()));
                result.setCertificateProfileName(certificateProfileIdToNameMap.get(userData.getCertificateProfileId()));
                result.setCaName(caSession.getCAIdToNameMap().get(userData.getCaId()));
                EndEntityType endEntityType = new EndEntityType(userData.getType());
                result.setNotificationConfigured(endEntityType.contains(EndEntityTypes.SENDNOTIFICATION));
                if (userData.getExtendedInformation() != null && userData.getExtendedInformation().getKeyStoreAlgorithmType() != null) {
                    result.setKeyAlgorithmPreSet(true);
                } else {
                    CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(userData.getCertificateProfileId());
                    result.setAvailableKeyAlgorithms(certificateProfile.getAvailableKeyAlgorithmsAsList());
                    result.setAvailableBitLengths(certificateProfile.getAvailableBitLengthsAsList());
                    result.setAvailableEcCurves(certificateProfile.getAvailableEcCurvesAsList());
                }
            }
            return result;
        }
        return null;
    }

    @Override
    public byte[] selfRenewCertificate(RaSelfRenewCertificateData renewCertificateData)
            throws AuthorizationDeniedException, EjbcaException, NoSuchEndEntityException, WaitingForApprovalException,
            CertificateSerialNumberException, EndEntityProfileValidationException, IllegalNameException,
            CADoesntExistsException {
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal(
                "RenewSelfCertificate", renewCertificateData.getClientIPAddress()));
        EndEntityInformation userData = endEntityAccessSession.findUser(admin, renewCertificateData.getUsername());
        if (userData.getType().contains(EndEntityTypes.SENDNOTIFICATION)) {
            EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(userData.getEndEntityProfileId());
            userData.setPassword(profile.makeAutoGeneratedPassword());
        } else {
            userData.setPassword(renewCertificateData.getPassword());
        }
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(admin, userData, false);
        userData.setTokenType(EndEntityConstants.TOKEN_SOFT_P12);
        if (userData.getExtendedInformation() == null || userData.getExtendedInformation().getKeyStoreAlgorithmType() == null) {
            if (userData.getExtendedInformation() == null) {
                userData.setExtendedInformation(new ExtendedInformation());
            }
            userData.getExtendedInformation().setKeyStoreAlgorithmType(renewCertificateData.getKeyAlg());
            userData.getExtendedInformation().setKeyStoreAlgorithmSubType(renewCertificateData.getKeySpec());
        }
        return generateKeyStoreWithoutViewEndEntityAccessRule(admin, userData);
    }

    @Override
    public RaEndEntityProfileResponse getEndEntityProfile(AuthenticationToken authenticationToken, final String profileName) throws EndEntityProfileNotFoundException, AuthorizationDeniedException {
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(profileName);
        if (endEntityProfileSession.isAuthorizedToView(authenticationToken, endEntityProfileId)) {
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(profileName);
            RaEndEntityProfileResponse.RaEndEntityProfileResponseConverter converter = RaEndEntityProfileResponse.converter();
            return converter.toRaResponse(profileName, endEntityProfile, caSession.getCAIdToNameMap(),
                    certificateProfileSession.getCertificateProfileIdToNameMap());
        } else {
            throw new AuthorizationDeniedException("User " + authenticationToken.toString() + " was not authorized to view certificate profile " + profileName);
        }
    }
}
