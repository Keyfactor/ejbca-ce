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
package org.ejbca.core.ejb.ra;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.naming.InvalidNameException;
import javax.persistence.EntityManager;
import javax.persistence.OptimisticLockException;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.transaction.Synchronization;
import javax.transaction.TransactionSynchronizationRegistry;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.audit.log.dto.SecurityEventProperties;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CABase;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.config.EABConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.ValidationException;
import org.cesecore.keys.validation.ValidationResult;
import org.cesecore.roles.member.RoleMemberData;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.PrintableStringNameStyle;
import org.cesecore.util.RFC4683Tools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenMetaData;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistoryData;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.EndEntityInformationFiller;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.FieldValidator;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.UserNotificationParamGen;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.ICustomNotificationRecipient;
import org.ejbca.core.model.ra.raadmin.UserNotification;
import org.ejbca.util.dn.DistinguishedName;
import org.ejbca.util.mail.MailException;
import org.ejbca.util.mail.MailSender;

/**
 * Manages end entities in the database using UserData Entity Bean.
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityManagementSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityManagementSessionBean implements EndEntityManagementSessionLocal, EndEntityManagementSessionRemote {
    private static final Logger log = Logger.getLogger(EndEntityManagementSessionBean.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    @Resource
    private TransactionSynchronizationRegistry registry;
    private PerTransactionData perTransactionData;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertReqHistorySessionLocal certreqHistorySession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession;
    @EJB
    private RevocationSessionLocal revocationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;

    private enum UserDataChangeMode {
        IGNORE,
        IF_NO_CONFLICT,
        MANDATORY_CHANGE
    }

    @PostConstruct
    public void postConstruct() {
        perTransactionData = new PerTransactionData(registry);
    }

    /** Gets the Global Configuration from ra admin session bean */
    private GlobalConfiguration getGlobalConfiguration() {
        return (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    @Override
    public EndEntityInformation initializeEndEntityTransaction(final String username) {
        EndEntityInformation existingUser = endEntityAccessSession.findUser(username);
        existingUser = (existingUser != null ? new EndEntityInformation(existingUser) : null);
        final OriginalEndEntity originalInfo = new OriginalEndEntity(existingUser);
        perTransactionData.setOriginalEndEntity(username, originalInfo);
        return existingUser;
    }

    @Override
    public void addUser(final AuthenticationToken authenticationToken,
                        final String username,
                        final String password,
                        final String subjectDn,
                        final String subjectAltName,
                        final String email,
                        final boolean clearPwd,
                        final int endEntityProfileId,
                        final int certificateProfileId,
                        final EndEntityType type,
                        final int tokenType,
                        final int caId)
            throws EndEntityExistsException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, CustomFieldException, IllegalNameException,
            ApprovalException, CertificateSerialNumberException {
        final EndEntityInformation userdata = new EndEntityInformation(username, subjectDn, caId, subjectAltName, email, EndEntityConstants.STATUS_NEW,
                type, endEntityProfileId, certificateProfileId, null, null, tokenType, null);
        userdata.setPassword(password);
        addUser(authenticationToken, userdata, clearPwd);
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ADDUSER = {
            new ApprovalOveradableClassName(
                    org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest.class.getName(),
                    null
            )
    };

    @Deprecated
    @Override
    public void addUserFromWS(final AuthenticationToken authenticationToken, EndEntityInformation userdata, final boolean clearPwd)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException, WaitingForApprovalException,
            CADoesntExistsException, CustomFieldException, IllegalNameException, ApprovalException, CertificateSerialNumberException {
        final int profileId = userdata.getEndEntityProfileId();
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(profileId);
        if (profile.getAllowMergeDn()) {
            userdata = EndEntityInformationFiller.fillUserDataWithDefaultValues(userdata, profile);
        }
        addUser(authenticationToken, userdata, clearPwd);
    }

    @Override
    public EndEntityInformation canonicalizeUser(final EndEntityInformation endEntity) throws CustomFieldException {
        // Make a deep copy
        EndEntityInformation endEntityInformationCopy = new EndEntityInformation(endEntity);
        final int endEntityProfileId = endEntityInformationCopy.getEndEntityProfileId();
        final String endEntityProfileName = endEntityProfileSession.getEndEntityProfileName(endEntityProfileId);
        FieldValidator.validate(endEntity, endEntityProfileId, endEntityProfileName);
        final String dn = CertTools.stringToBCDNString(StringTools.strip(endEntityInformationCopy.getDN()));
        endEntityInformationCopy.setDN(dn);
        endEntityInformationCopy.setSubjectAltName(StringTools.strip(endEntityInformationCopy.getSubjectAltName()));
        endEntityInformationCopy.setEmail(StringTools.strip(endEntityInformationCopy.getEmail()));
        return endEntityInformationCopy;
    }

    @Override
    public void addUserAfterApproval(
            AuthenticationToken authenticationToken, EndEntityInformation userdata,
            boolean clearPwd, AuthenticationToken lastApprovingAdmin
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, EndEntityExistsException,
            WaitingForApprovalException, CADoesntExistsException, CustomFieldException, IllegalNameException,
            ApprovalException, CertificateSerialNumberException {
        addUser(authenticationToken, userdata, clearPwd, lastApprovingAdmin);
    }

    @Override
    public EndEntityInformation addUser(
            final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final boolean clearPwd
    ) throws AuthorizationDeniedException, EndEntityExistsException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, CustomFieldException, IllegalNameException,
            ApprovalException, CertificateSerialNumberException {
        return addUser(authenticationToken, endEntity, clearPwd, null);
    }

    /**
     *
     * @throws ApprovalException if an approval already exists for this request.
     * @throws AuthorizationDeniedException if the admin is not authorized to the CA, or lacks rights to add end entities.
     * @throws CADoesntExistsException if the CA specified does not exist
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws EndEntityExistsException if the end entity already exists
     * @throws IllegalNameException if the Subject DN failed constraints
     * @throws EndEntityProfileValidationException if the end entity fails constrains set by the end entity profile
     * @throws WaitingForApprovalException to mark that a request has been created and is awaiting approval. The request ID will be included as a field in this exception.
     */
    private EndEntityInformation addUser(final AuthenticationToken authenticationToken,
                                         EndEntityInformation endEntity,
                                         final boolean clearPwd,
                                         final AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, EndEntityExistsException, EndEntityProfileValidationException,
            WaitingForApprovalException, CADoesntExistsException, CustomFieldException, IllegalNameException,
            ApprovalException, CertificateSerialNumberException {
        final int endEntityProfileId = endEntity.getEndEntityProfileId();
        final int caId = endEntity.getCAId();
        // Check if administrator is authorized to add user to CA.
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        final GlobalConfiguration globalConfiguration = getGlobalConfiguration();
        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to add user.
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, endEntityProfileId, AccessRulesConstants.CREATE_END_ENTITY, caId);
        }

        final String originalDN = endEntity.getDN();
        // Keep the original, where we may set autogenerated username/password. This modifies the original object and thus 
        // made available to the caller even if return value is not used
        EndEntityInformation unCanonicalized = endEntity;
        endEntity = canonicalizeUser(endEntity);
        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
        endEntity.setSubjectAltName(getAddDnsFromCnToAltName(endEntity.getDN(), endEntity.getSubjectAltName(), profile));

        if( profile.getAllowMergeDn()) {
            endEntity = EndEntityInformationFiller.fillUserDataWithDefaultValues(endEntity, profile);
        }
        
        if (log.isTraceEnabled()) {
            log.trace(">addUser(" + endEntity.getUsername() + ", password, " + endEntity.getDN() + ", " + originalDN + ", " + endEntity.getSubjectAltName()
                    + ", " + endEntity.getEmail() + ", profileId: " + endEntityProfileId + ")");
        }

        final String endEntityProfileName = endEntityProfileSession.getEndEntityProfileName(endEntityProfileId);
        if (endEntityProfileName == null) {
            throw new EndEntityProfileValidationException("End Entity profile " + endEntityProfileId + " does not exist trying to add user: " + endEntity.getUsername());
        }
        final String dn = endEntity.getDN();
        String altName = endEntity.getSubjectAltName();
        try {
            altName =  RFC4683Tools.generateSimForInternalSanFormat(altName);
        } catch(Exception e) {
            log.info("Could not generate SIM string for SAN: " + altName, e);
            throw new EndEntityProfileValidationException("Could not generate SIM string for SAN: " + e.getMessage(), e);
        }
        if (log.isTraceEnabled()) {
            log.trace("addUser(calculated SIM: " + altName + ")");
        }
        final String email = endEntity.getEmail();
        final EndEntityType type = endEntity.getType();
        String newpassword = endEntity.getPassword();
        if (endEntity.getPassword() == null) {
            if (profile.useAutoGeneratedPasswd()) {
                // special case used to signal regeneration of password
                newpassword = profile.makeAutoGeneratedPassword();
            }
        }
        // Autogenerate username if it's not modifiable and it's empty
        if(StringUtils.isBlank(endEntity.getUsername())){
            if (profile.isAutoGeneratedUsername()) {
                final byte[] randomData = new byte[16];
                final Random random = new SecureRandom();
                random.nextBytes(randomData);
                String autousername = new String(Hex.encode(randomData));
                while (endEntityAccessSession.findUser(autousername) != null) {
                    if(log.isDebugEnabled()){
                        log.debug("Autogenerated username '" + autousername + "' is already reserved. Generating the new one...");
                    }
                    random.nextBytes(randomData);
                    autousername = new String(Hex.encode(randomData));
                }
                if(log.isDebugEnabled()){
                    log.debug("Unique username '" + autousername + "' has been generated");
                }
                unCanonicalized.setUsername(autousername);
                endEntity.setUsername(autousername);
            }
        }
        // Trim
        endEntity.setUsername(StringTools.trim(endEntity.getUsername()));
        final String username = endEntity.getUsername();
        unCanonicalized.setUsername(username);
        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntity.getCertificateProfileId());
            try {
                final String dirAttrs = endEntity.getExtendedInformation() != null ? endEntity.getExtendedInformation()
                        .getSubjectDirectoryAttributes() : null;
                final EABConfiguration eabConfiguration = (EABConfiguration) globalConfigurationSession.getCachedConfiguration(EABConfiguration.EAB_CONFIGURATION_ID);
                profile.doesUserFulfillEndEntityProfile(username, endEntity.getPassword(), dn, altName, dirAttrs, email,
                        endEntity.getCertificateProfileId(), clearPwd, type.contains(EndEntityTypes.KEYRECOVERABLE),
                        type.contains(EndEntityTypes.SENDNOTIFICATION), endEntity.getTokenType(), caId,
                        endEntity.getExtendedInformation(), certProfile, eabConfiguration);
            } catch (EndEntityProfileValidationException e) {
                logAuditEvent(
                        EjbcaEventTypes.RA_ADDENDENTITY, EventStatus.FAILURE,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder()
                                .withMsg(intres.getLocalizedMessage("ra.errorfulfillprofile", endEntityProfileName, dn, e.getMessage()))
                                .build()
                );
                throw e;
            }
        }
        // Get CAInfo, to be able to read configuration
        // No need to access control on the CA here just to get these flags, we have already checked above that we are authorized to the CA
        final CA ca = (CA) caSession.getCAInternal(caId, null, null, true);
        if (ca == null) {
            throw new CADoesntExistsException("CA with ID " + caId + " does not exist.");
        }
        final CAInfo caInfo = ca.getCAInfo();

        // Check name constraints
        if (caInfo instanceof X509CAInfo && caInfo.getCertificateChain() != null && !caInfo.getCertificateChain().isEmpty()) {
            final X509CAInfo x509cainfo = (X509CAInfo) caInfo;
            final X509Certificate caCert = (X509Certificate)caInfo.getCertificateChain().iterator().next();
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntity.getCertificateProfileId());

            final X500NameStyle nameStyle;
            if (x509cainfo.getUsePrintableStringSubjectDN()) {
                nameStyle = PrintableStringNameStyle.INSTANCE;
            } else {
                nameStyle = CeSecoreNameStyle.INSTANCE;
            }

            // will cause an error to be thrown later if name constraints are used
            final boolean ldapOrder = x509cainfo.getUseLdapDnOrder() && certProfile.getUseLdapDnOrder();

            X500Name subjectDNName = CertTools.stringToBcX500Name(dn, nameStyle, ldapOrder);
            GeneralNames subjectAltName = CertTools.getGeneralNamesFromAltName(altName);
            try {
                CABase.checkNameConstraints(caCert, subjectDNName, subjectAltName);
            } catch (IllegalNameException e) {
                e.setErrorCode(ErrorCode.NAMECONSTRAINT_VIOLATION);
                throw e;
            }
        }
        
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntity.getCertificateProfileId());
        // Check if approvals is required. (Only do this if store users, otherwise this approval is disabled.)
        if (caInfo.isUseUserStorage()) {
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.ADDEDITENDENTITY, caInfo,
                    certProfile);
            if (approvalProfile != null) {
                final List<ValidationResult> validationResults = runApprovalRequestValidation(authenticationToken, endEntity, ca);
                final AddEndEntityApprovalRequest ar = new AddEndEntityApprovalRequest(endEntity, clearPwd, authenticationToken, null, caId,
                        endEntityProfileId, approvalProfile, validationResults);
                // How come we pass through here when the request is actually approved?
                // When the approval request is finally executed, it is executed through AddEndEntityApprovalRequest.execute, which is
                // the NONAPPROVABLECLASSNAMES_ADDUSER below.
                if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ADDUSER)) {
                    final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                    sendNotification(authenticationToken, endEntity, EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL, requestId, lastApprovingAdmin, null);
                    throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalad"), requestId);
                }
            }
        }
        // Check if the subjectDN serialnumber already exists.
        if (caInfo.isDoEnforceUniqueSubjectDNSerialnumber()) {
            if (caInfo.isUseUserStorage()) {
                if (!isSubjectDnSerialnumberUnique(caId, dn, username)) {
                    throw new CertificateSerialNumberException("Error: SubjectDN serial number already exists.");
                }
            } else {
                log.warn("CA configured to enforce unique SubjectDN serialnumber, but not to store any user data. Check will be ignored. Please verify your configuration.");
            }
        }
        
        // Store a new UserData in the database, if this CA is configured to do so.
        // Store it in case of the OCSPSIGNER certificate profile anyway, since otherwise OCSP signer renewal via peers won't work for throwaway CAs
        if (caInfo.isUseUserStorage() || (certProfile.getUseExtendedKeyUsage() && !CollectionUtils.isEmpty(certProfile.getExtendedKeyUsageOids())
                        && certProfile.getExtendedKeyUsageOids().contains(KeyPurposeId.id_kp_OCSPSigning.getId()))) {
            try {
                final ExtendedInformation extendedInformation = endEntity.getExtendedInformation();
                ensureOldClusterNodeCompatibility(extendedInformation);
                // Create the user in one go with all parameters at once. This was important in EJB2.1 so the persistence layer only creates *one*
                // single
                // insert statement. If we do a home.create and the some setXX, it will create one insert and one update statement to the database.
                // Probably not important in EJB3 anymore.
                final UserData userData = new UserData(username, newpassword, clearPwd, dn, caId, endEntity.getCardNumber(), altName, email, type.getHexValue(),
                        endEntityProfileId, endEntity.getCertificateProfileId(), endEntity.getTokenType(), extendedInformation);
                // Since persist will not commit and fail if the user already exists, we need to check for this
                // Flushing the entityManager will not allow us to rollback the persisted user if this is a part of a larger transaction.
                if (existsUser(userData.getUsername())){
                    throw new EndEntityExistsException("User " + userData.getUsername() + " already exists.");
                }
                if (!perTransactionData.couldSuppressUserDataModification(username)) {
                    entityManager.persist(userData);
                } else {
                    // Instead of calling entityManager.persist() here, we use a beforeCompletion callback
                    // that gets called at the end of the transaction.
                    // This is necessary since we want to remove the UserData entity from the transaction
                    // in some cases (see suppressUnwantedUserDataChanges()).
                    perTransactionData.setPendingUserData(userData);
                    registry.registerInterposedSynchronization(new Synchronization() {
                        @Override
                        public void beforeCompletion() {
                            final UserData user = perTransactionData.getPendingUserData(username);
                            if (user != null) {
                                log.debug("Adding end-entity in beforeCompletion of transaction");
                                entityManager.persist(userData);
                                entityManager.flush();
                            } else {
                                log.debug("Not adding end-entity in beforeCompletion of transaction");
                            }
                            perTransactionData.clearEndEntityTransactionInfo(username);
                        }
                        @Override
                        public void afterCompletion(final int transactionStatus) {
                        }
                    });
                }
                // Although EndEntityInformation should always have a null password for
                // autogenerated end entities, the notification framework
                // expect it to exist. Since nothing else but printing is done after
                // this point it is safe to set the password
                unCanonicalized.setPassword(newpassword);
                endEntity.setPassword(newpassword);
                // This is an add user request, if there was an approval involved in add user, it will have been added to extendedInformation
                int approvalRequestID = 0;
                if (endEntity.getExtendedInformation() != null && endEntity.getExtendedInformation().getAddEndEntityApprovalRequestId() != null) {
                    approvalRequestID = endEntity.getExtendedInformation().getAddEndEntityApprovalRequestId();
                }
                sendNotification(authenticationToken, endEntity, EndEntityConstants.STATUS_NEW, approvalRequestID, lastApprovingAdmin, null);
                logAuditEvent(
                        EjbcaEventTypes.RA_ADDENDENTITY, EventStatus.SUCCESS,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder()
                                .withMsg(intres.getLocalizedMessage("ra.addedentity", username))
                                .withCustomMap(endEntity.getDetailMap())
                                .build()
                );
            } catch (EndEntityExistsException e) {
                logAuditEvent(
                        EjbcaEventTypes.RA_ADDENDENTITY, EventStatus.FAILURE,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder().withMsg(intres.getLocalizedMessage("ra.errorentityexist", username)).build()
                );
                throw e;
            } catch (Exception e) {
                final String msg = intres.getLocalizedMessage("ra.erroraddentity", username);
                log.error(msg, e);
                logAuditEvent(
                        EjbcaEventTypes.RA_ADDENDENTITY, EventStatus.FAILURE,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder().withMsg(msg).withError(e.getMessage()).build()
                );
                throw new EJBException(e);
            }
        } else if (log.isDebugEnabled()) {
            log.debug("User storage disabled on CA '"+caInfo.getName()+"', user with username '"+username+"' is not stored.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<addUser(" + username + ", password, " + dn + ", " + email + ")");
        }
        return endEntity;
    }

    private List<ValidationResult> runApprovalRequestValidation(
            final AuthenticationToken authenticationToken, final UserData userdata, final CA ca
    ) throws ApprovalException {
        if (ca == null || CollectionUtils.isEmpty(ca.getValidators())) {
            return Collections.emptyList();
        }
        final EndEntityInformation endEntity = userdata.toEndEntityInformation();
        try {
            return keyValidatorSession.validateDnsNames(authenticationToken, IssuancePhase.APPROVAL_VALIDATION, ca, endEntity, null);
        } catch (ValidationException e) {
            // Only configurations with "Approval Request" issuance phase and "Abort issuance" failure action will go here.
            // Since this is a very unlikely configuration, we do not use a separate exception.
            throw new ApprovalException(ErrorCode.VALIDATION_FAILED, e.getMessage(), e);
        }
    }

    private List<ValidationResult> runApprovalRequestValidation(
            final AuthenticationToken authenticationToken, final EndEntityInformation endEntity, final CA ca
    ) throws ApprovalException {
        try {
            return keyValidatorSession.validateDnsNames(authenticationToken, IssuancePhase.APPROVAL_VALIDATION, ca, endEntity, null);
        } catch (ValidationException e) {
            // Only configurations with "Approval Request" issuance phase and "Abort issuance" failure action will go here.
            // Since this is a very unlikely configuration, we do not use a separate exception.
            throw new ApprovalException(ErrorCode.VALIDATION_FAILED, e.getMessage(), e);
        }
    }

    /* Does not check authorization. Calling code is responsible for this. */
    private boolean isSubjectDnSerialnumberUnique(final int caId, final String subjectDN, final String username) {
        final String serialnumber = CertTools.getPartFromDN(subjectDN, "SN");
        if (log.isDebugEnabled()) {
            log.debug("subjectDN=" + subjectDN + " extracted SN=" + serialnumber);
        }
        // We treat the lack of a serialnumber field as unique
        if (serialnumber == null) {
            return true;
        }
        // Without a username we cannot determine if this is the same user, if we find any in the database later
        if (username == null) {
            return false;
        }
        final List<String> subjectDNs = endEntityAccessSession.findSubjectDNsByCaIdAndNotUsername(caId, username, serialnumber);
        // Even though we push down most of the work to the database we still have to verify the serialnumber here since
        // for example serialnumber '1' will match both "SN=1" and "SN=10" etc
        for (final String currentSubjectDN : subjectDNs) {
            final String currentSn = CertTools.getPartFromDN(currentSubjectDN, "SN");
            if (serialnumber.equals(currentSn)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean renameEndEntity(
            final AuthenticationToken authenticationToken, String currentUsername, String newUsername
    ) throws AuthorizationDeniedException, EndEntityExistsException {
        // Sanity check parameters
        if (currentUsername == null || newUsername == null) {
            throw new IllegalArgumentException("Cannot rename an end entity to or from null.");
        }
        currentUsername = StringTools.stripUsername(currentUsername).trim();
        newUsername = StringTools.stripUsername(newUsername).trim();
        if (currentUsername.length() == 0 || newUsername.length() == 0) {
            throw new IllegalArgumentException("Cannot rename an end entity to or from empty string.");
        }
        // Check that end entity exists and that the target username isn't already in use
        final UserData currentUserData = endEntityAccessSession.findByUsername(currentUsername);
        if (currentUserData == null) {
            return false;
        }
        if (endEntityAccessSession.findByUsername(newUsername) !=null) {
            throw new EndEntityExistsException("Unable to rename end entity, since end entity with username '" + newUsername + "' already exists.");
        }
        // Check authorization
        final int currentCaId = currentUserData.getCaId();
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, currentCaId);
        final GlobalConfiguration globalConfiguration = getGlobalConfiguration();
        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to edit user.
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, currentUserData.getEndEntityProfileId(), AccessRulesConstants.EDIT_END_ENTITY, currentCaId);
        }
        // Rename the end entity. Username is a primary key of the UserData table and we need to use JPA for this to get rowProtection.
        // we need to add a new end entity and remove the old one.
        perTransactionData.clearEndEntityTransactionInfo(currentUsername);
        final long now = System.currentTimeMillis();
        final UserData userDataClone = currentUserData.clone();
        userDataClone.setUsername(newUsername);
        userDataClone.setTimeModified(now);
        entityManager.persist(userDataClone);
        entityManager.remove(currentUserData);
        // Find all entities and update the username (we cant just do UPDATE ... SET username.. WHERE username since rowProtection might be enabled)
        final List<CertificateData> certificateDatas = entityManager.createQuery(
                "SELECT a FROM CertificateData a WHERE a.username=:username", CertificateData.class).setParameter("username", currentUsername).getResultList();
        int updatedPublisherQueueDataRows = 0;
        for (final CertificateData certificateData : certificateDatas) {
            final String fingerprint = certificateData.getFingerprint();
            certificateData.setUsername(newUsername);
            certificateData.setUpdateTime(now);
            // Find all publisher queue data where PublisherQueueData.fingerprint matches CertificateData.fingerprint for this user
            final List<PublisherQueueData> publisherQueueDatas = PublisherQueueData.findDataByFingerprint(entityManager, fingerprint);
            for (final PublisherQueueData publisherQueueData : publisherQueueDatas) {
                // Only process entries that has not yet been published/processed
                if (publisherQueueData.getPublishStatus()==PublisherConst.STATUS_PENDING) {
                    final PublisherQueueVolatileInformation volatileInformation = publisherQueueData.getPublisherQueueVolatileData();
                    if (currentUsername.equals(volatileInformation.getUsername())) {
                        volatileInformation.setUsername(newUsername);
                        // Invoke setter to trigger update of still managed JPA entity
                        publisherQueueData.setPublisherQueueVolatileData(volatileInformation);
                        updatedPublisherQueueDataRows++;
                    }
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Changed username '" + currentUsername + "' to '" + newUsername + "' in " + certificateDatas.size() + " rows of CertificateData.");
            log.debug("Changed username '" + currentUsername + "' to '" + newUsername + "' in " + updatedPublisherQueueDataRows + " rows of PublisherQueueData.");
        }
        final List<CertReqHistoryData> certReqHistoryDatas = entityManager.createQuery(
                "SELECT a FROM CertReqHistoryData a WHERE a.username=:username", CertReqHistoryData.class).setParameter("username", currentUsername).getResultList();
        for (final CertReqHistoryData current : certReqHistoryDatas) {
            // Note: Ignore the username inside certReqHistoryData.getUserDataVO(), since this should reflect the state of the UserData at the time of certificate issuance
            current.setUsername(newUsername);
        }
        if (log.isDebugEnabled()) {
            log.debug("Changed username '" + currentUsername + "' to '" + newUsername + "' in " + certReqHistoryDatas.size() + " rows of CertReqHistoryData.");
        }
        final List<KeyRecoveryData> keyRecoveryDatas = entityManager.createQuery(
                "SELECT a FROM KeyRecoveryData a WHERE a.username=:username", KeyRecoveryData.class).setParameter("username", currentUsername).getResultList();
        for (final KeyRecoveryData current : keyRecoveryDatas) {
            current.setUsername(newUsername);
        }
        if (log.isDebugEnabled()) {
            log.debug("Changed username '" + currentUsername + "' to '" + newUsername + "' in " + keyRecoveryDatas.size() + " rows of KeyRecoveryData.");
        }
        // Update CLI admins where this username is used in AdminEntityData table.
        final List<RoleMemberData> roleMemberDatas = entityManager.createQuery(
                "SELECT a FROM RoleMemberData a WHERE a.tokenType=:tokenType AND a.tokenMatchKey=:tokenMatchKey AND a.tokenMatchValueColumn=:tokenMatchValue", RoleMemberData.class)
                .setParameter("tokenType", CliAuthenticationTokenMetaData.TOKEN_TYPE)
                .setParameter("tokenMatchKey", CliUserAccessMatchValue.USERNAME.getNumericValue())
                .setParameter("tokenMatchValue", currentUsername)
                .getResultList();
        for (final RoleMemberData current : roleMemberDatas) {
            current.setTokenMatchValue(newUsername);
        }
        if (log.isDebugEnabled()) {
            log.debug("Changed username '" + currentUsername + "' to '" + newUsername + "' in " + roleMemberDatas.size() + " rows of RoleMemberData.");
        }
        logAuditEvent(
                EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                authenticationToken, currentCaId, newUsername, currentUsername,
                SecurityEventProperties.builder()
                        .withMsg(intres.getLocalizedMessage("ra.editedentityrename", currentUsername, newUsername))
                        .build()
        );
        return true;
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_CHANGEUSER = {
            new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest.class.getName(), null),
            // can not use .class.getName() below, because it is not part of base EJBCA dist
            new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection", null)
    };

    @Override
    public void changeUserAfterApproval(
            final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation,
            final boolean clearPwd, final int approvalRequestId, final AuthenticationToken lastApprovingAdmin
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException {
        changeUser(authenticationToken, endEntityInformation, clearPwd, false, approvalRequestId, lastApprovingAdmin, null, false);
    }

    @Override
    public void changeUserAfterApproval(
            final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation,
            final boolean clearPwd, final int approvalRequestId, final AuthenticationToken lastApprovingAdmin, String oldUsername
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException {
        String newUsername = endEntityInformation.getUsername();
        endEntityInformation.setUsername(oldUsername);
        changeUser(authenticationToken, endEntityInformation, clearPwd, false, approvalRequestId, lastApprovingAdmin, newUsername, false);
    }

    @Override
    public void changeUser(
            final AuthenticationToken authenticationToken, final EndEntityInformation userdata, final boolean clearPwd
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException {
        changeUser(authenticationToken, userdata, clearPwd, false);
    }

    @Override
    public void changeUser(
            final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation,
            final boolean clearPwd, final boolean fromWebService
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException {
        changeUser(authenticationToken, endEntityInformation, clearPwd, fromWebService, 0, null, null, false);
    }


    @Override
    public void changeUser(
            final AuthenticationToken authenticationToken, final EndEntityInformation userdata, final boolean clearPwd,
            final String newUsername
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException,
            ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException {
        changeUser(authenticationToken, userdata, clearPwd, false, 0, null, newUsername, false);
    }
    
    @Override
    public void changeUserIgnoreApproval(
            AuthenticationToken admin, EndEntityInformation endEntityInformation, boolean clearPwd
    ) throws ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException {
        changeUser(admin, endEntityInformation, clearPwd, false, 0, null, null, true);
    }

    /**
     * Change user information
     * 
     * @param authenticationToken an authentication token
     * @param endEntityInformation the end entity being modified
     * @param clearPwd true if using a cleartext password
     * @param fromWebService if this request comes from the web service API
     * @param approvalRequestId the approval request ID associated with this change. 0 if none.
     * @param lastApprovingAdmin the last approval, null if none
     * @param newUsername the new usename, if any. null if none
     * @param force true if approvals are to be ignored. <b>Only</b> to be used in internal operations.
     * @throws AuthorizationDeniedException if the administrator was not authorized to this operation
     * @throws EndEntityProfileValidationException the end entity profile associated with this end entity did not exist
     * @throws WaitingForApprovalException thrown if this operation requires further approval
     * @throws ApprovalException thrown if this operation is already awaiting approval
     * @throws CertificateSerialNumberException if the serial number in the subject DN was not unique
     * @throws IllegalNameException if the any of the fields in the DN or altName did not follow name constraints, or if the username was already taken
     * @throws NoSuchEndEntityException if the end entity specified as a parameter did not exist in the database
     * @throws CustomFieldException if the changes invalidae the EEP 
     */
    private void changeUser(
            final AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation,
            final boolean clearPwd, final boolean fromWebService, final int approvalRequestId,
            final AuthenticationToken lastApprovingAdmin, final String newUsername, final boolean force
    ) throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, ApprovalException,
            CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException {
        final int endEntityProfileId = endEntityInformation.getEndEntityProfileId();
        final int caId = endEntityInformation.getCAId();
        String username = endEntityInformation.getUsername();
        // Check if administrator is authorized to edit user to CA.
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        final GlobalConfiguration globalConfiguration = getGlobalConfiguration();
        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to edit user.
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, endEntityProfileId, AccessRulesConstants.EDIT_END_ENTITY, caId);
        }

        final String eeProfileName = endEntityProfileSession.getEndEntityProfileName(endEntityProfileId);
        if (eeProfileName == null) {
            throw new EndEntityProfileValidationException("End Entity profile " + endEntityProfileId + " does not exist trying to change user: " + username);
        }
        FieldValidator.validate(endEntityInformation, endEntityProfileId, eeProfileName);
        
        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
        String dn = CertTools.stringToBCDNString(StringTools.strip(endEntityInformation.getDN()));
        String altName = endEntityInformation.getSubjectAltName();
        if (log.isTraceEnabled()) {
            log.trace(">changeUser(" + username + ", " + dn + ", " + endEntityInformation.getEmail() + ")");
        }
        try {
            altName =  RFC4683Tools.generateSimForInternalSanFormat(altName);
        } catch(Exception e) {
             log.info("Could not generate SIM string for SAN: " + altName, e);
             throw new EndEntityProfileValidationException("Could not generate SIM string for SAN: " + e.getMessage(), e);
        }
        if (log.isTraceEnabled()) {
            log.trace(">changeUser(calculated SIM: " + altName + ")");
        }
        UserData userData = endEntityAccessSession.findByUsername(username);
        if (userData == null) {
            final String msg = intres.getLocalizedMessage("ra.erroreditentity", username);
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        final EndEntityInformation originalCopy = new EndEntityInformation(userData.toEndEntityInformation());
        
        // Merge all DN and SAN values from previously saved end entity
        if (profile.getAllowMergeDn()) {
            try {
                // SubjectDN is not mandatory so
                if (dn == null) {
                    dn = "";
                }
                final Map<String, String> sdnMap = new HashMap<>();
                if (profile.getUse(DnComponents.DNEMAILADDRESS, 0)) {
                    sdnMap.put(DnComponents.DNEMAILADDRESS, endEntityInformation.getEmail());
                }
                              
                dn = new DistinguishedName(userData.getSubjectDnNeverNull()).mergeDN(new DistinguishedName(dn), true, sdnMap).toString();
                dn = EndEntityInformationFiller.getDnEntriesUniqueOnly(dn, EndEntityInformationFiller.SUBJECT_DN);

            } catch (InvalidNameException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Subject DN when merging '"+dn+"' with '"+userData.getSubjectDnNeverNull()+"'. Setting it to empty. Exception was: " + e.getMessage());
                }
                dn = "";
            }
            try {
                // SubjectAltName is not mandatory so
                if (altName == null) {
                    altName = "";
                }
                final Map<String, String> sanMap = new HashMap<>();
                if (profile.getUse(DnComponents.RFC822NAME, 0)) {
                    sanMap.put(DnComponents.RFC822NAME, endEntityInformation.getEmail());
                }
                altName = new DistinguishedName(userData.getSubjectAltNameNeverNull()).mergeDN(new DistinguishedName(altName), true, sanMap).toString();
                altName = EndEntityInformationFiller.getDnEntriesUniqueOnly(altName, EndEntityInformationFiller.SUBJECT_ALTERNATIVE_NAME);
            } catch (InvalidNameException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Subject AN when merging '"+altName+"' with '"+userData.getSubjectAltNameNeverNull()+"'. Setting it to empty. Exception was: " + e.getMessage());
                }
                altName = "";
            }

        }
        
        altName = getAddDnsFromCnToAltName(dn, altName, profile);
        String newPassword = endEntityInformation.getPassword();
        if (profile.useAutoGeneratedPasswd() && newPassword != null) {
            // special case used to signal regeneraton of password
            newPassword = profile.makeAutoGeneratedPassword();
        }

        final EndEntityType type = endEntityInformation.getType();
        final ExtendedInformation extendedInformation = endEntityInformation.getExtendedInformation();
        final String trimmedNewUsername = StringTools.trim(newUsername);

        // Check if user fulfills it's profile.
        if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
            try {
                String dirAttrs = null;
                if (extendedInformation != null) {
                    dirAttrs = extendedInformation.getSubjectDirectoryAttributes();
                }

                // User change might include a new username
                final String usernameToValidate = StringUtils.isEmpty(trimmedNewUsername) ? username : trimmedNewUsername;

                final EABConfiguration eabConfiguration = (EABConfiguration) globalConfigurationSession.getCachedConfiguration(EABConfiguration.EAB_CONFIGURATION_ID);

                // It is only meaningful to verify the password if we change it in some way, and if we are not autogenerating it
                if (!profile.useAutoGeneratedPasswd() && StringUtils.isNotEmpty(newPassword)) {
                    profile.doesUserFulfillEndEntityProfile(usernameToValidate, endEntityInformation.getPassword(), dn, altName, dirAttrs, endEntityInformation.getEmail(),
                            endEntityInformation.getCertificateProfileId(), clearPwd, type.contains(EndEntityTypes.KEYRECOVERABLE),
                            type.contains(EndEntityTypes.SENDNOTIFICATION), endEntityInformation.getTokenType(), caId, extendedInformation, certProfile, eabConfiguration);
                } else {
                    profile.doesUserFulfillEndEntityProfileWithoutPassword(usernameToValidate, dn, altName, dirAttrs, endEntityInformation.getEmail(),
                            endEntityInformation.getCertificateProfileId(), type.contains(EndEntityTypes.KEYRECOVERABLE),
                            type.contains(EndEntityTypes.SENDNOTIFICATION), endEntityInformation.getTokenType(), caId, extendedInformation, certProfile, eabConfiguration);
                }
            } catch (EndEntityProfileValidationException e) {
                logAuditEvent(
                        EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.FAILURE,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder()
                                .withMsg(intres.getLocalizedMessage("ra.errorfulfillprofile", endEntityProfileId, dn, e.getMessage()))
                                .build()
                );
                throw e;
            }
        }
        // Check name constraints
        final CA ca = (CA) caSession.getCAInternal(caId, null, null, true);
        if (ca == null) {
            throw new EndEntityProfileValidationException("CA with ID " + caId + " doesn't exist.");
        }
        final CAInfo caInfo = ca.getCAInfo();
        final boolean nameChanged = // only check when name is changed so existing end-entities can be changed even if they violate NCs
                !userData.getSubjectDnNeverNull().equals(CertTools.stringToBCDNString(dn)) ||
                (userData.getSubjectAltName() != null && !userData.getSubjectAltName().equals(altName));
        if (nameChanged && caInfo instanceof X509CAInfo && !caInfo.getCertificateChain().isEmpty()) {
            final X509CAInfo x509cainfo = (X509CAInfo) caInfo;
            final X509Certificate cacert = (X509Certificate)caInfo.getCertificateChain().iterator().next();
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(userData.getCertificateProfileId());

            final X500NameStyle nameStyle;
            if (x509cainfo.getUsePrintableStringSubjectDN()) {
                nameStyle = PrintableStringNameStyle.INSTANCE;
            } else {
                nameStyle = CeSecoreNameStyle.INSTANCE;
            }

            // will cause an error to be thrown later if name constraints are used
            final boolean ldapOrder = x509cainfo.getUseLdapDnOrder() && (certProfile != null && certProfile.getUseLdapDnOrder());

            X500Name subjectDNName = CertTools.stringToBcX500Name(dn, nameStyle, ldapOrder);
            GeneralNames subjectAltName = CertTools.getGeneralNamesFromAltName(altName);
            try {
                CABase.checkNameConstraints(cacert, subjectDNName, subjectAltName);
            } catch (IllegalNameException e) {
                e.setErrorCode(ErrorCode.NAMECONSTRAINT_VIOLATION);
                throw e;
            }
        }
        if(!force) {
            // Check if approvals are required.
            final CertificateProfile certificateProfile = certificateProfileSession
                    .getCertificateProfile(endEntityInformation.getCertificateProfileId());
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.ADDEDITENDENTITY, caInfo,
                    certificateProfile);
            if (approvalProfile != null) {
                final EndEntityInformation orguserdata = userData.toEndEntityInformation();
                final EndEntityInformation requestInfo = new EndEntityInformation(endEntityInformation);
                if (trimmedNewUsername != null && !trimmedNewUsername.equals(username)) {
                    requestInfo.setUsername(trimmedNewUsername);
                }
                final List<ValidationResult> validationResults = runApprovalRequestValidation(authenticationToken, requestInfo, ca);
                final EditEndEntityApprovalRequest ar = new EditEndEntityApprovalRequest(requestInfo, clearPwd, orguserdata, authenticationToken, null, caId,
                        endEntityProfileId, approvalProfile, validationResults);
                if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_CHANGEUSER)) {
                    final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                    throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvaledit"), requestId);
                }
            }
        }
        // Rename the end entity if there's a new username
        if (trimmedNewUsername != null && !trimmedNewUsername.equals(username)) {
            boolean success;
            try {
                success = renameEndEntity(authenticationToken, username, trimmedNewUsername);
            } catch (EndEntityExistsException e) {
                throw new IllegalNameException("Username already taken");
            }
            if (!success) {
                throw new NoSuchEndEntityException("End entity does not exist");
            }
            username = trimmedNewUsername;
            userData = endEntityAccessSession.findByUsername(username);
        }
        // Check if the subjectDN serialnumber already exists.
        // No need to access control on the CA here just to get these flags, we have already checked above that we are authorized to the CA
        if (caInfo.isDoEnforceUniqueSubjectDNSerialnumber()) {
            if (!isSubjectDnSerialnumberUnique(caId, dn, username)) {
                throw new CertificateSerialNumberException("Error: SubjectDN Serialnumber already exists.");
            }
        }

        try {
            userData.setDN(dn);
            userData.setSubjectAltName(altName);
            userData.setSubjectEmail(endEntityInformation.getEmail());
            userData.setCaId(caId);
            userData.setType(type.getHexValue());
            userData.setEndEntityProfileId(endEntityProfileId);
            userData.setCertificateProfileId(endEntityInformation.getCertificateProfileId());
            userData.setTokenType(endEntityInformation.getTokenType());
            userData.setCardNumber(endEntityInformation.getCardNumber());
            final int newStatus = endEntityInformation.getStatus();
            final int oldStatus = userData.getStatus();
            if (oldStatus == EndEntityConstants.STATUS_KEYRECOVERY && newStatus != EndEntityConstants.STATUS_KEYRECOVERY
                    && newStatus != EndEntityConstants.STATUS_INPROCESS) {
                keyRecoverySession.unmarkUser(authenticationToken, username);
            }
            if (extendedInformation != null) {
                final String requestCounter = extendedInformation.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
                if (StringUtils.equals(requestCounter, "0") && newStatus == EndEntityConstants.STATUS_NEW && oldStatus != EndEntityConstants.STATUS_NEW) {
                    // If status is set to new, we should re-set the allowed request counter to the default values
                    // But we only do this if no value is specified already, i.e. 0 or null
                    resetRequestCounter(false, extendedInformation, username, endEntityProfileId);
                } else {
                    // If status is not new, we will only remove the counter if the profile does not use it
                    resetRequestCounter(true, extendedInformation, username, endEntityProfileId);
                }

                // Make sure that information about related approval requests are carried over to the edited end entity.
                // This is done to make it possible to  trace/find an approval request from the actually added/edited end entity
                final ExtendedInformation oldExtendedInfo = userData.getExtendedInformation();
                if(oldExtendedInfo != null) {
                    List<Integer> editApprovalReqIds = oldExtendedInfo.getEditEndEntityApprovalRequestIds();
                    for(Integer id : editApprovalReqIds) {
                        extendedInformation.addEditEndEntityApprovalRequestId(id);
                    }

                    Integer addApprovalReqId = oldExtendedInfo.getAddEndEntityApprovalRequestId();
                    if(addApprovalReqId != null) {
                        extendedInformation.setAddEndEntityApprovalRequestId(addApprovalReqId);
                    }
                }
            }
            ensureOldClusterNodeCompatibility(extendedInformation);
            userData.setExtendedInformation(extendedInformation);
            userData.setStatus(newStatus);
            if (StringUtils.isNotEmpty(newPassword)) {
                if (clearPwd) {
                    userData.setOpenPassword(newPassword);
                } else {
                    userData.setPassword(newPassword);
                }
            }
            // We want to create this object before re-setting the time modified, because we may want to
            // use the old time modified in any notifications
            final EndEntityInformation notificationEndEntityInformation = userData.toEndEntityInformation();
            userData.setTimeModified(new Date().getTime());
            perTransactionData.setPendingUserData(userData);
            // We also want to be able to handle non-clear generated passwords in the notification, although EndEntityInformation
            // should always have a null password for autogenerated end entities the notification framework expects it to
            // exist.
            if (newPassword != null) {
                notificationEndEntityInformation.setPassword(newPassword);
            }
            // Send notification if it should be sent.
            sendNotification(authenticationToken, notificationEndEntityInformation, newStatus, approvalRequestId, lastApprovingAdmin, null);
            // Logging details object
            // Make a diff of what was changed to we can log it
            // We need to set times so that diffing is made properly, also use the latest notificationEndEntity so that we include potential DN merging, 
            // i.e. diff the original to what we actually stored in the database
            notificationEndEntityInformation.setTimeModified(new Date(userData.getTimeModified()));
            notificationEndEntityInformation.setTimeCreated(new Date(userData.getTimeCreated()));
            final Map<String, String[]> diff = originalCopy.getDiff(notificationEndEntityInformation);
            final Map<String, String> auditDiffCustomMap = new LinkedHashMap<>();
            for(String key : diff.keySet()) {
                auditDiffCustomMap.put(key, diff.get(key)[0] + " -> " + diff.get(key)[1]);
            }
            // Add the diff later on, in order to have it after the "msg"
            if (newStatus != oldStatus) {
                logAuditEvent(
                        EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder()
                                .withMsg(intres.getLocalizedMessage("ra.editedentitystatus", username, newStatus))
                                .withCustomMap(auditDiffCustomMap)
                                .build()
                );
            } else {
                logAuditEvent(
                        EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                        authenticationToken, caId, null, username,
                        SecurityEventProperties.builder()
                                .withMsg(intres.getLocalizedMessage("ra.editedentity", username))
                                .withCustomMap(auditDiffCustomMap)
                                .build()
                );
            }
        } catch (Exception e) {
            logAuditEvent(
                    EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.FAILURE,
                    authenticationToken, caId, null, username,
                    SecurityEventProperties.builder()
                            .withMsg(intres.getLocalizedMessage("ra.erroreditentity", username))
                            .withError(e.getMessage())
                            .build()
            );
            log.error("ChangeUser:", e);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeUser(" + username + ", password, " + dn + ", " + endEntityInformation.getEmail() + ")");
        }
    }

    /**
     * Update subjectAltName with dns fields with value from CN
     * @param subjectDn subjectDn
     * @param altName altName
     * @param profile EEProfile
     * @return altName updated with dns copied from CN
     */
    private String getAddDnsFromCnToAltName(final String subjectDn, String altName, final EndEntityProfile profile) {
        String dnsNameValueFromCn = EndEntityInformationFiller.copyDnsNameValueFromCn(profile, subjectDn);
        if (altName == null) {
            altName = "";
        }
        if (StringUtils.isNotEmpty(dnsNameValueFromCn) && !altName.contains(dnsNameValueFromCn)) {
       
            if (StringUtils.isNotEmpty(altName)) {
                altName += ", ";
            }
        altName += dnsNameValueFromCn;
        }
        
        return altName;
    }

    @Override
    public void deleteUser(final AuthenticationToken authenticationToken, final String username)
            throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {  
        final String trimmedUsername = StringTools.trim(username);
        if (log.isTraceEnabled()) {
            log.trace(">deleteUser(" + trimmedUsername + ")");
        }
        // Check if administrator is authorized to delete user.
        Integer caId;
        final UserData data1 = endEntityAccessSession.findByUsername(trimmedUsername);
        if (data1 != null) {
            caId = data1.getCaId();
            endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
            if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
                endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, data1.getEndEntityProfileId(), AccessRulesConstants.DELETE_END_ENTITY, caId);
            }
        } else {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", trimmedUsername));
            // This exception message is used to not leak information to the user
            final String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        try {
            entityManager.remove(data1);
            logAuditEvent(
                    EjbcaEventTypes.RA_DELETEENDENTITY, EventStatus.SUCCESS,
                    authenticationToken, caId, null, trimmedUsername,
                    SecurityEventProperties.builder().withMsg(intres.getLocalizedMessage("ra.removedentity", trimmedUsername)).build()
            );
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("ra.errorremoveentity", trimmedUsername);
            logAuditEvent(
                    EjbcaEventTypes.RA_DELETEENDENTITY, EventStatus.FAILURE,
                    authenticationToken, caId, null, trimmedUsername,
                    SecurityEventProperties.builder().withMsg(msg).withError(e.getMessage()).build()
            );
            throw new CouldNotRemoveEndEntityException(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<deleteUser(" + trimmedUsername + ")");
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS = {
            new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest.class.getName(), null),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "revokeUser"),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "revokeUserAfterApproval"),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "revokeCert"),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionBean.class.getName(), "finishUser"),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "unrevokeCert"),
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "prepareForKeyRecovery"),
            // can not use .class.getName() below, because it is not part of base EJBCA dist
            new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess", "processExtRARevocationRequest"),
            new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection", null)
    };

    @Override
    public int decRequestCounter(String username) throws NoSuchEndEntityException, ApprovalException, WaitingForApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">decRequestCounter(" + username + ")");
        }
        // Default return value is as if the optional value does not exist for
        // the user, i.e. the default values is 0
        // because the default number of allowed requests are 1
        int counter = 0;
        // Check if administrator is authorized to edit user.
        UserData data1 = endEntityAccessSession.findByUsername(username);
        if (data1 != null) {
            // Do the work of decreasing the counter
            ExtendedInformation ei = data1.getExtendedInformation();
            if (ei != null) {
                String counterstr = ei.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
                boolean serialNumberCleared = false;
                if (StringUtils.isNotEmpty(counterstr)) {
                    try {
                        counter = Integer.parseInt(counterstr);
                        if (log.isDebugEnabled()) {
                            log.debug("Found a counter with value " + counter);
                        }
                        // decrease the counter, if we get to 0 we must set
                        // status to generated
                        counter--;
                        if (counter >= 0) {
                            ei.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, String.valueOf(counter));
                            ei.setCertificateSerialNumber(null);// cert serial number should also be cleared after successful command.
                            data1.setExtendedInformation(ei);
                            serialNumberCleared = true;
                            final Date now = new Date();
                            if (counter > 0) { // if 0 then update when changing type
                                data1.setTimeModified(now.getTime());
                            }
                            String msg = intres.getLocalizedMessage("ra.decreasedentityrequestcounter", username, counter);
                            log.info(msg);
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Counter value was already 0, not decreased in db.");
                            }
                        }
                    } catch (NumberFormatException e) {
                        String msg = intres.getLocalizedMessage("ra.errorrequestcounterinvalid", username, counterstr, e.getMessage());
                        log.error(msg, e);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No (optional) request counter exists for end entity: " + username);
                    }
                }
                if (!serialNumberCleared && ei.certificateSerialNumber() != null) {
                    ei.setCertificateSerialNumber(null);// cert serial number should also be cleared after successful command.
                    data1.setExtendedInformation(ei);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No extended information exists for user: " + data1.getUsername());
                }
            }
        } else {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            // This exception message is used to not leak information to the user
            String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        if (counter <= 0) {
            AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Local admin call from EndEntityManagementSession.decRequestCounter"));
            setUserStatus(admin, data1, EndEntityConstants.STATUS_GENERATED, 0, null);
        }
        suppressUnwantedUserDataChanges(perTransactionData.getOriginalEndEntity(username), data1);
        if (log.isTraceEnabled()) {
            log.trace("<decRequestCounter(" + username + "): " + counter);
        }
        return counter;
    }

    @Override
    public void suppressUnwantedUserDataChanges(final String username) {
        final OriginalEndEntity originalInfo = perTransactionData.getOriginalEndEntity(username);
        if (originalInfo != null) { // We should always update for status changes, so we must update if the original state is not known
            final UserData newUserData = endEntityAccessSession.findByUsername(username);
            suppressUnwantedUserDataChanges(originalInfo, newUserData);
        }
    }

    private void suppressUnwantedUserDataChanges(final OriginalEndEntity originalEndEntity, final UserData newUserData) {
        switch (classifyUserDataChanges(originalEndEntity, newUserData)) {
        case IGNORE:
            entityManager.detach(newUserData);
            break;
        case IF_NO_CONFLICT:
            entityManager.detach(newUserData);
            try {
                endEntityManagementSession.changeUserInNewTransaction(newUserData, !originalEndEntity.isExisting());
            } catch (EJBException e) {
                if (e.getCause() instanceof OptimisticLockException) {
                    log.info("User '" + newUserData.getUsername() + "' was updated in concurrent transaction, and will not be updated. The OptimisticLockException was ignored.");
                } else {
                    throw e;
                }
            }
            break;
        case MANDATORY_CHANGE:
            // Keep the UserData changes in the current transaction
            if (perTransactionData.getPendingUserData(newUserData.getUsername()) != null) {
                entityManager.persist(newUserData);
            }
            break;
        }
        perTransactionData.clearEndEntityTransactionInfo(newUserData.getUsername());
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void changeUserInNewTransaction(final UserData newUserData, final boolean isNew) {
            if (isNew) {
                entityManager.persist(newUserData);
            } else {
                entityManager.merge(newUserData);
            }
    }

    /**
     * Classifies a change in the UserData table:
     * <ul>
     * <li>Actual status changes result in MANDATORY_CHANGE, to ensure that NEW -> GENERATED changes are updated in the database.
     * <li>Other changes, and new additions of end-entities, result in IF_NO_CONFLICT.
     * <li>IGNORE is returned when there are no changes (besides timestamp update etc.)
     */
    private UserDataChangeMode classifyUserDataChanges(final OriginalEndEntity originalInfo, final UserData newUserData) {
        // We should always update for status changes, so we must update if the original state is not known
        if (originalInfo == null) {
            return UserDataChangeMode.MANDATORY_CHANGE;
        }
        // Always add new end-entities
        if (!originalInfo.isExisting()) {
            return UserDataChangeMode.IF_NO_CONFLICT;
        }
        final EndEntityInformation newCopy = newUserData.toEndEntityInformation();
        final EndEntityInformation originalCopy = originalInfo.getEndEntity();
        // Force update on actual status change
        if (newUserData.getStatus() != originalCopy.getStatus()) {
            return UserDataChangeMode.MANDATORY_CHANGE;
        }
        // Force update on request counter change
        final ExtendedInformation newExtendedInfo = newUserData.getExtendedInformation();
        final ExtendedInformation oldExtendedInfo = originalCopy.getExtendedInformation();
        if ((newExtendedInfo != null) != (oldExtendedInfo != null)) {
            return UserDataChangeMode.MANDATORY_CHANGE;
        }
        if (newExtendedInfo != null) {
            if (!StringUtils.equals(
                    newExtendedInfo.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER),
                    oldExtendedInfo.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER))) {
                return UserDataChangeMode.MANDATORY_CHANGE;
            }
        }
        // Modification time is ignored
        newCopy.setTimeModified(originalCopy.getTimeModified());
        if (newUserData.getStatus() == EndEntityConstants.STATUS_GENERATED) {
            // Passwords are ignored because they are typically hashed.
            // This is only safe to do if the end-entity will end in GENERATED state.
            originalCopy.setPassword(null);
            newCopy.setPassword(null);
        }
        final Map<String, String[]> diff = originalCopy.getDiff(newCopy);
        UserDataChangeMode changeMode = UserDataChangeMode.IGNORE;
        for (final Map.Entry<String,String[]> entry : diff.entrySet()) {
            final String[] values = entry.getValue();
            final String oldValue = values[0];
            final String newValue = values[1];
            // Sometimes we end up with (null, "") or ("", null) here.
            // For example with SubjectAltName, but lets handle it for all attributes.
            if (StringUtils.trimToNull(oldValue) == null && StringUtils.trimToNull(newValue) == null) {
                continue;
            }
            if (log.isDebugEnabled()) {
                log.debug("Key " + entry.getKey() + " has changed from '" + oldValue + "' to '" + newValue + "'. Will update end-entity");
            }
            changeMode = UserDataChangeMode.IF_NO_CONFLICT;
        }
        if (log.isDebugEnabled() && changeMode == UserDataChangeMode.IGNORE) {
            log.debug("Will not update UserData of '" + originalCopy.getUsername() + "' because there are no changes.");
        }
        return changeMode;
    }

    @Override
    public void cleanUserCertDataSN(String userName) throws NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">cleanUserCertDataSN(" + userName + ")");
        }
        try {
            // Check if administrator is authorized to edit user.
            final UserData data = endEntityAccessSession.findByUsername(userName);
            if (data != null) {
                final ExtendedInformation extendedInformation = data.getExtendedInformation();
                if (extendedInformation == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No extended information exists for user: " + userName);
                    }
                } else {
                    extendedInformation.setCertificateSerialNumber(null);
                    data.setExtendedInformation(extendedInformation);
                }
            } else {
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", userName));
                // This exception message is used to not leak information to the user
                String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
                log.info(msg);
                throw new NoSuchEndEntityException(msg);
            }
        } catch (NoSuchEndEntityException e) {
            String msg = intres.getLocalizedMessage("authentication.usernotfound", userName);
            log.info(msg);
            throw new NoSuchEndEntityException(e.getMessage());
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<cleanUserCertDataSN(" + userName + ")");
            }
        }
    }
    
    @Override
    public void cleanSerialnumberAndCsrFromUserData(String userName) throws NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">cleanUserCertDataSN(" + userName + ")");
        }
        try {
            // Check if administrator is authorized to edit user.
            UserData data = endEntityAccessSession.findByUsername(userName);
            if (data != null) {
                final ExtendedInformation ei = data.getExtendedInformation();
                if (ei == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No extended information exists for user: " + data.getUsername());
                    }
                } else {
                    ei.setCertificateSerialNumber(null);
                    ei.setCertificateRequest(null);
                    data.setExtendedInformationPrePersist(ei);
                }
            } else {
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", userName));
                // This exception message is used to not leak information to the user
                String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
                log.info(msg);
                throw new NoSuchEndEntityException(msg);
            }
        } catch (NoSuchEndEntityException e) {
            String msg = intres.getLocalizedMessage("authentication.usernotfound", userName);
            log.info(msg);
            throw new NoSuchEndEntityException(e.getMessage());
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<cleanUserCertDataSN(" + userName + ")");
            }
        }
    }
    
    @Override
    public void setUserStatus(final AuthenticationToken admin, final String username, final int status) throws AuthorizationDeniedException,
            ApprovalException, WaitingForApprovalException, NoSuchEndEntityException {
        setUserStatusAfterApproval(admin, username, status, 0, null);
    }

    @Override
    public void setUserStatusAfterApproval(final AuthenticationToken admin, final String username, final int status, final int approvalRequestID,
            final AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">setUserStatus(" + username + ", " + status + ")");
        }
        // Check if administrator is authorized to edit user.
        final UserData data = endEntityAccessSession.findByUsername(username);
        if (data == null) {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            // This exception message is used to not leak information to the user
            final String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        // Check authorization
        final int caid = data.getCaId();
        endEntityAuthenticationSession.assertAuthorizedToCA(admin, caid);
        if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.EDIT_END_ENTITY, caid);
        }
        setUserStatus(admin, data, status, approvalRequestID, lastApprovingAdmin);
    }

    @Override
    public void setUserStatus(
            final AuthenticationToken authenticationToken, final UserData data1, final int status,
            final int approvalRequestID, final AuthenticationToken lastApprovingAdmin
    ) throws ApprovalException, WaitingForApprovalException {
        final int caId = data1.getCaId();
        // Get CAInfo, to be able to read configuration of approval proiles and validators.
        // No need to access control on the CA here just to get these flags, we have already checked above that we are authorized to the CA
        final CA ca = (CA) caSession.getCAInternal(caId, null, null, true);
        final CAInfo caInfo = ca != null ? ca.getCAInfo() : null;

        final String username = data1.getUsername();
        final int endEntityProfileId = data1.getEndEntityProfileId();
        // Check if approvals is required.
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(data1.getCertificateProfileId());
        final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.ADDEDITENDENTITY, caInfo,
                certProfile);
        if (approvalProfile != null) {
            List<ValidationResult> validationResults = null;
            if (status != EndEntityConstants.STATUS_GENERATED && status != EndEntityConstants.STATUS_FAILED && status != EndEntityConstants.STATUS_REVOKED) {
                // Run validators when changing to NEW or similar, but not when revoking or after cert generation. 
                validationResults = runApprovalRequestValidation(authenticationToken, data1, ca);
            }
            final ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest(username, data1.getStatus(), status, authenticationToken,
                    null, data1.getCaId(), endEntityProfileId, approvalProfile, validationResults);
            if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS)) {
                final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                String msg = intres.getLocalizedMessage("ra.approvaledit");
                throw new WaitingForApprovalException(msg, requestId);
            }
        }
        if (data1.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY
                && !(status == EndEntityConstants.STATUS_KEYRECOVERY || status == EndEntityConstants.STATUS_INPROCESS || status == EndEntityConstants.STATUS_INITIALIZED)) {
            keyRecoverySession.unmarkUser(authenticationToken, username);
        }
        if ((status == EndEntityConstants.STATUS_NEW) && (data1.getStatus() != EndEntityConstants.STATUS_NEW)) {
            final ExtendedInformation extendedInformation = data1.getExtendedInformation();
            if (extendedInformation != null) {
                // If status is set to new, when it is not already new, we should
                // re-set the allowed request counter to the default values
                final boolean counterChanged = resetRequestCounter(false, extendedInformation, username, endEntityProfileId);
                // Reset remaining login counter
                final boolean resetChanged = UserData.resetRemainingLoginAttemptsInternal(extendedInformation, username);
                if (counterChanged || resetChanged) {
                    // TimeModified is set finally below, since this method sets status as well
                    // data1.setTimeModified(new Date().getTime());
                    data1.setExtendedInformation(extendedInformation);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Status not changing from something else to new, not resetting requestCounter.");
            }
        }

        if(approvalRequestID != 0) {
            ExtendedInformation ei = data1.getExtendedInformation();
            if(ei == null) {
                ei = new ExtendedInformation();
            }
            ei.addEditEndEntityApprovalRequestId(approvalRequestID);
            data1.setExtendedInformation(ei);
        }

        final Date timeModified = new Date();
        data1.setStatus(status);
        data1.setTimeModified(timeModified.getTime());
        perTransactionData.setPendingUserData(data1);
        logAuditEvent(
                EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                authenticationToken, caId, null, username,
                SecurityEventProperties.builder()
                        .withMsg(intres.getLocalizedMessage("ra.editedentitystatus", username, status))
                        .build()
        );
        // Send notifications when transitioning user through work-flow, if they
        // should be sent
        final EndEntityInformation userdata = data1.toEndEntityInformation();
        sendNotification(authenticationToken, userdata, status, 0, lastApprovingAdmin, null);
        if (log.isTraceEnabled()) {
            log.trace("<setUserStatus(" + username + ", " + status + ")");
        }
    }

    @Override
    public void setPassword(
            AuthenticationToken authenticationToken, String username, String password
    ) throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException {
        setPassword(authenticationToken, username, password, false);
    }

    @Override
    public void setClearTextPassword(
            AuthenticationToken authenticationToken, String username, String password
    ) throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException {
        setPassword(authenticationToken, username, password, true);
    }

    /**
     * Sets a password, hashed or clear text, for a user.
     *
     * @param authenticationToken the administrator performing the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting password to 'null' effectively deletes any previous clear text password.
     * @param clearText true gives cleartext password, false hashed
     */
    private void setPassword(
            final AuthenticationToken authenticationToken, final String username, final String password, final boolean clearText
    ) throws EndEntityProfileValidationException, AuthorizationDeniedException, NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">setPassword(" + username + ", hiddenpwd), " + clearText);
        }
        // Find user
        String newPasswd = password;
        final UserData data = endEntityAccessSession.findByUsername(username);
        if (data == null) {
            throw new NoSuchEndEntityException("Could not find user " + username);
        }
        final int caId = data.getCaId();
        final int endEntityProfileId = data.getEndEntityProfileId();

        final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
        if (profile != null) {
            if (profile.useAutoGeneratedPasswd()) {
                newPasswd = profile.makeAutoGeneratedPassword();
            }
        }
        if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            if (profile != null) {
                try {
                    profile.doesPasswordFulfillEndEntityProfile(password, true);
                } catch (EndEntityProfileValidationException e) {
                    final String dn = data.getSubjectDnNeverNull();
                    auditSession.log(
                            EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.FAILURE,
                            EjbcaModuleTypes.RA, ServiceTypes.CORE,
                            authenticationToken.toString(), String.valueOf(caId), null, username,
                            intres.getLocalizedMessage("ra.errorfulfillprofile", endEntityProfileId, dn, e.getMessage())
                    );
                    throw e;
                }
            }
            // Check if administrator is authorized to edit user.
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, data.getEndEntityProfileId(), AccessRulesConstants.EDIT_END_ENTITY, caId);
        }
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        try {
            final Date now = new Date();
            if ((newPasswd == null) && (clearText)) {
                data.setClearPassword("");
                data.setPasswordHash("");
            } else {
                if (clearText) {
                    data.setOpenPassword(newPasswd);
                } else {
                    data.setPassword(newPasswd);
                }
            }
            data.setTimeModified(now.getTime());
            logAuditEvent(
                    EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                    authenticationToken, caId, null, username,
                    SecurityEventProperties.builder().withMsg(intres.getLocalizedMessage("ra.editpwdentity", username)).build()
            );
        } catch (NoSuchAlgorithmException nsae) {
            log.error("NoSuchAlgorithmException while setting password for user " + username);
            throw new EJBException(nsae);
        }
        if (log.isTraceEnabled()) {
            log.trace("<setPassword(" + username + ", hiddenpwd), " + clearText);
        }
    }

    @Override
    public void updateCAId(
            final AuthenticationToken authenticationToken, final String username, int newCaId
    ) throws AuthorizationDeniedException, NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">updateCAId(" + username + ", " + newCaId +")");
        }
        // Find user
        final UserData data = endEntityAccessSession.findByUsername(username);
        if (data == null) {
            throw new NoSuchEndEntityException("Could not find user " + username);
        }
        int oldCaId = data.getCaId();
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, oldCaId);
        data.setCaId(newCaId);
        logAuditEvent(
                EjbcaEventTypes.RA_EDITENDENTITY, EventStatus.SUCCESS,
                authenticationToken, oldCaId, null, username,
                SecurityEventProperties.builder()
                        .withMsg(intres.getLocalizedMessage("ra.updatedentitycaid", username, oldCaId, newCaId))
                        .build()
        );
        if (log.isTraceEnabled()) {
            log.trace(">updateCAId(" + username + ", " + newCaId + ")");
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKEANDDELETEUSER = {
            new ApprovalOveradableClassName(
                    org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(),
                    null
            )
    };

    @Override
    public void revokeAndDeleteUser(
            AuthenticationToken authenticationToken, String username, int reason
    ) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, NoSuchEndEntityException,
            CouldNotRemoveEndEntityException {
        final UserData data = endEntityAccessSession.findByUsername(username);
        if (data == null) {
            throw new NoSuchEndEntityException("User '" + username + "' not found.");
        }
        // Authorized?
        final int caId = data.getCaId();
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, data.getEndEntityProfileId(), AccessRulesConstants.REVOKE_END_ENTITY, caId);
        }

        if (data.getStatus() != EndEntityConstants.STATUS_REVOKED) {
            // Check if approvals is required.
            CAInfo cainfo = caSession.getCAInfoInternal(caId, null, true);
            if(cainfo == null) {
                // If CA does not exist, the user is a bit "weird", but things can happen in reality and CAs can disappear
                // So the CA not existing should not prevent us from revoking the user.
                // It may however affect the possible Approvals, but we probably need to be able to do this in order to clean up a bad situation
                log.info("Trying to revokeAndDelete an End Entity connected to a CA, with ID " + caId + ", that does not exist.");
            }
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(data.getCertificateProfileId());
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.REVOCATION, cainfo,
                    certProfile);
            if (approvalProfile != null) {
                final RevocationApprovalRequest ar = new RevocationApprovalRequest(true, username, reason, authenticationToken, caId, data.getEndEntityProfileId(),
                        approvalProfile);
                if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKEANDDELETEUSER)) {
                    final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                    throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalrevoke"), requestId);
                }
            }
            try {
                revokeUser(authenticationToken, username, reason);
            } catch (AlreadyRevokedException e) {
                // This just means that the end entity was revoked before
                // this request could be completed. No harm.
            }
        }
        deleteUser(authenticationToken, username);
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKEUSER = {
            new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.EndEntityManagementSessionBean.class.getName(), "revokeAndDeleteUser"),
            new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(), null)
    };

    @Override
    public void revokeUser(final AuthenticationToken authenticationToken, final String username, final int reason, final boolean deleteUser) throws AuthorizationDeniedException, CADoesntExistsException, WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException, EjbcaException {
        // Check username.
        final EndEntityInformation userdata = endEntityAccessSession.findUser(authenticationToken,username);
        if(userdata == null) {
            throw new NoSuchEndEntityException("User '" + username + "' not found.");
        }
        // Check CA ID.
        final int caId = userdata.getCAId();
        caSession.verifyExistenceOfCA(caId);
        // Authorization check is done later again in revokeUser..., and may be written to audit log.
        // The error messages differ and MUST NOT be changed here because of the call by RaMasterAPI and EJBCA WS.
        if(!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId)) {
            throw new AuthorizationDeniedException(intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caId, null));
        }
        if (deleteUser) {
            revokeAndDeleteUser(authenticationToken,username,reason);
        } else {
            revokeUser(authenticationToken,username,reason);
        }
    }

    @Override
    public void revokeUser(AuthenticationToken authenticationToken, String username, int reason) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        revokeUserAfterApproval(authenticationToken, username, reason, 0, null);
    }

    @Override
    public void revokeUserAfterApproval(AuthenticationToken authenticationToken, String username, int reason, final int approvalRequestID, final AuthenticationToken lastApprovingAdmin)
            throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        if (log.isTraceEnabled()) {
            log.trace(">revokeUser(" + username + ")");
        }
        final UserData userData = endEntityAccessSession.findByUsername(username);
        if (userData == null) {
            throw new NoSuchEndEntityException("Could not find user " + username);
        }
        final int caId = userData.getCaId();
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
            endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, userData.getEndEntityProfileId(), AccessRulesConstants.REVOKE_END_ENTITY, caId);
        }

        if ((userData.getStatus() == EndEntityConstants.STATUS_REVOKED) && !RevokedCertInfo.isRevoked(reason)) {
            final String msg = intres.getLocalizedMessage("ra.errorinvalidrevokereason", userData.getUsername(), reason);
            log.info(msg);
            throw new AlreadyRevokedException(msg);
        }

        // Check if approvals is required.
        CAInfo caInfo = caSession.getCAInfoInternal(caId, null, true);
        if(caInfo == null) {
            // If CA does not exist, the user is a bit "weird", but things can happen in reality and CAs can disappear
            // So the CA not existing should not prevent us from revoking the user.
            // It may however affect the possible Approvals, but we probably need to be able to do this in order to clean up a bad situation
            log.info("Trying to revoke an End Entity connected to a CA, with ID "+caId+", that does not exist.");
        }
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(userData.getCertificateProfileId());
        final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.REVOCATION, caInfo, certProfile);
        if (approvalProfile != null) {
            final RevocationApprovalRequest ar = new RevocationApprovalRequest(false, username, reason, authenticationToken, caId, userData.getEndEntityProfileId(),
                    approvalProfile);
            if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKEUSER)) {
                final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalrevoke"), requestId);
            }
        }
        // Revoke all non-expired and not revoked certs, one at the time
        final EndEntityInformation endEntityInformation = userData.toEndEntityInformation();
        final List<CertificateDataWrapper> cdws = certificateStoreSession.getCertificateDataByUsername(username, true, Arrays.asList(CertificateConstants.CERT_ARCHIVED, CertificateConstants.CERT_REVOKED));
        for (final CertificateDataWrapper cdw : cdws) {
            try {
                final Certificate certificate = cdw.getCertificate();
                final BigInteger serialNumber;
                if (certificate == null) {
                    try {
                        // This will work for X.509
                        serialNumber = new BigInteger(cdw.getCertificateData().getSerialNumber(), 10);
                    } catch (NumberFormatException e) {
                        throw new UnsupportedOperationException();
                    }
                } else {
                    serialNumber = CertTools.getSerialNumber(certificate);
                }
                try {
                    revokeCert(authenticationToken, serialNumber, null, /*invalidityDate*/ null, cdw.getCertificateData().getIssuerDN(), reason, false, endEntityInformation, 0, lastApprovingAdmin, null);
                } catch (RevokeBackDateNotAllowedForProfileException e) {
                    throw new IllegalStateException("This should not happen since there is no back dating.",e);
                } catch (CertificateProfileDoesNotExistException e) {
                    throw new IllegalStateException("This should not happen since this method overload does not support certificateProfileId input parameter.",e);
                }
            } catch (AlreadyRevokedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Certificate from issuer '" + cdw.getCertificateData().getIssuerDN() + "' with serial " + cdw.getCertificateData().getSerialNumber()
                            + " was already revoked.");
                }
            }
        }

        if(approvalRequestID != 0) {
            ExtendedInformation ei = userData.getExtendedInformation();
            if(ei == null) {
                ei = new ExtendedInformation();
            }
            ei.addRevokeEndEntityApprovalRequestId(approvalRequestID);
            userData.setExtendedInformation(ei);
        }

        // Finally set revoke status on the user as well
        try {
            setUserStatus(authenticationToken, userData, EndEntityConstants.STATUS_REVOKED, 0, lastApprovingAdmin);
        } catch (ApprovalException | WaitingForApprovalException e) {
            throw new IllegalStateException("This should never happen", e);
        }
        logAuditEvent(
                EjbcaEventTypes.RA_REVOKEDENDENTITY, EventStatus.SUCCESS,
                authenticationToken, caId, null, username,
                SecurityEventProperties.builder().withMsg(intres.getLocalizedMessage("ra.revokedentity", username)).build()
        );
        if (log.isTraceEnabled()) {
            log.trace("<revokeUser()");
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKECERT = {
            new ApprovalOveradableClassName(
                    org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(),
                    null
            )
    };

    @Override
    public void revokeCert(
            final AuthenticationToken authenticationToken, final BigInteger certSerNo, final String issuerDn, final int reason
    ) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            AlreadyRevokedException {
        try {
            revokeCert(authenticationToken, certSerNo, null, /*invalidityDate*/null, issuerDn, reason, false);
        } catch (RevokeBackDateNotAllowedForProfileException e) {
            throw new IllegalStateException("This should not happen since there is no back dating.",e);
        }
    }

    @Override
    public void revokeCertAfterApproval(
            final AuthenticationToken authenticationToken, final BigInteger certSerNo, final String issuerDn,
            final int reason, final int approvalRequestID, final AuthenticationToken lastApprovingAdmin, 
            final Date revocationDate, final Date invalidityDate
    ) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            AlreadyRevokedException {
        try {
            revokeCert(authenticationToken, certSerNo, revocationDate, invalidityDate, issuerDn, reason, false, null, approvalRequestID, lastApprovingAdmin, null);
        } catch (RevokeBackDateNotAllowedForProfileException e) {
            throw new IllegalStateException("Back dating is not allowed in Certificate Profile",e);
        } catch (CertificateProfileDoesNotExistException e) {
            throw new IllegalStateException("This should not happen since this method overload does not support certificateProfileId input parameter.",e);
        }
    }

    @Override
    public void revokeCert(
            AuthenticationToken authenticationToken, BigInteger certSerNo, Date revocationDate, Date invalidityDate, String issuerDn,
            int reason, boolean checkDate
    ) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException {
        try {
            revokeCert(authenticationToken, certSerNo, revocationDate, invalidityDate, issuerDn, reason, checkDate, null, 0, null, null);
        } catch (CertificateProfileDoesNotExistException e) {
            throw new IllegalStateException("This should not happen since this method overload does not support certificateProfileId input parameter.",e);
        }
    }

    @Override
    public void revokeCertWithMetadata(
            AuthenticationToken authenticationToken, CertRevocationDto certRevocationDto
    ) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CertificateProfileDoesNotExistException {
        BigInteger certificateSn = new BigInteger(certRevocationDto.getCertificateSN(), 16);
        
        revokeCert(authenticationToken, certificateSn, certRevocationDto.getRevocationDate(), certRevocationDto.getInvalidityDate(), 
                certRevocationDto.getIssuerDN(), certRevocationDto.getReason(), certRevocationDto.isCheckDate(), null, 0, null, 
                certRevocationDto.getCertificateProfileId());
    }

    private void revokeCert(
            AuthenticationToken authenticationToken, BigInteger certSerNo, Date revocationDate, Date invalidityDate, String issuerDn,
            int reason, boolean checkDate, final EndEntityInformation endEntityInformationParam, final int approvalRequestID,
            final AuthenticationToken lastApprovingAdmin, final Integer certificateProfileIdParam
    ) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CertificateProfileDoesNotExistException {
        if (log.isTraceEnabled()) {
            log.trace(">revokeCert(" + certSerNo.toString(16) + ", IssuerDN: " + issuerDn + ")");
        }
        // Check that the admin has revocation rights.
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
            final String msg = intres.getLocalizedMessage("ra.errorauthrevoke");
            logAuditEvent(
                    EventTypes.ACCESS_CONTROL, EventStatus.FAILURE,
                    authenticationToken, null, certSerNo.toString(16).toUpperCase(), null,
                    SecurityEventProperties.builder().withMsg(msg).build()
            );
            throw new AuthorizationDeniedException(msg);
        }

        // To be fully backwards compatible we just use the first fingerprint found..
        final CertificateDataWrapper cdw = noConflictCertificateStoreSession.getCertificateDataByIssuerAndSerno(issuerDn, certSerNo);
        if (cdw == null) {
            final String msg = intres.getLocalizedMessage("ra.errorfindentitycert", issuerDn, certSerNo.toString(16));
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        final BaseCertificateData certificateData = cdw.getBaseCertificateData();
        final int caId = certificateData.getIssuerDN().hashCode();
        final String username = certificateData.getUsername();
        endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, caId);
        final int revocationReason = certificateData.getRevocationReason();

        if (certificateProfileIdParam != null) {
            validateCertificateProfileExists(certificateProfileIdParam);
            certificateData.setCertificateProfileId(certificateProfileIdParam);
        }
        int certificateProfileId = certificateData.getCertificateProfileId();

        String certificateSubjectDN = certificateData.getSubjectDnNeverNull();
        final CertReqHistory certReqHistory = certreqHistorySession.retrieveCertReqHistory(certSerNo, issuerDn);
        int endEntityProfileId = certificateData.getEndEntityProfileIdOrZero();
        final EndEntityInformation endEntityInformation = endEntityInformationParam==null ? endEntityAccessSession.findUser(username) : endEntityInformationParam;
        if (certReqHistory == null) {
            if (endEntityInformation != null) {
                // If for some reason the end entity profile ID was not set in the certificate data, try to get it from current userdata
                // Get the EEP that is currently used as a fallback, if we can find it
                if (endEntityProfileId == EndEntityConstants.NO_END_ENTITY_PROFILE) {
                    endEntityProfileId = endEntityInformation.getEndEntityProfileId();
                }
                // Republish with the same user DN that is currently used as a fallback, if we can find it
                certificateSubjectDN = endEntityInformation.getCertificateDN();
                // If for some reason the certificate profile ID was not set in the certificate data, try to get it from current userdata
                if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                    certificateProfileId = endEntityInformation.getCertificateProfileId();
                }
            }
        } else {
            // If for some reason the end entity profile ID was not set in the certificate data, try to get it from current userdata
            // Get the EEP that was used in the original issuance, if we can find it
            if (endEntityProfileId == EndEntityConstants.NO_END_ENTITY_PROFILE) {
                endEntityProfileId = certReqHistory.getEndEntityInformation().getEndEntityProfileId();
            }
            // Republish with the same user DN that was used in the original publication, if we can find it
            certificateSubjectDN = certReqHistory.getEndEntityInformation().getCertificateDN();
            // If for some reason the certificate profile ID was not set in the certificate data, try to get it from the certreq history
            if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                certificateProfileId = certReqHistory.getEndEntityInformation().getCertificateProfileId();
            }
        }
        if (endEntityProfileId != EndEntityConstants.NO_END_ENTITY_PROFILE) {
            // We can only perform this check if we have a trail of what eep was used.
            if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
                endEntityAuthenticationSession.assertAuthorizedToEndEntityProfile(authenticationToken, endEntityProfileId, AccessRulesConstants.REVOKE_END_ENTITY, caId);
            }
        }
        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
        // Check if revocation can be backdated
        if (checkDate && revocationDate != null && revocationDate.getTime() != certificateData.getRevocationDate()
                && (certificateProfile == null || !certificateProfile.getAllowBackdatedRevocation())) {
            final String profileName = this.certificateProfileSession.getCertificateProfileName(certificateProfileId);
            final String msg = intres.getLocalizedMessage("ra.norevokebackdate", profileName, certSerNo.toString(16), issuerDn);
            throw new RevokeBackDateNotAllowedForProfileException(msg);
        }
        //Check if revocation includes invalidityDate and is allowed
        final CAInfo cainfo = caSession.getCAInfoInternal(caId, null, true);
        if (invalidityDate != null && !(cainfo.isAllowInvalidityDate())) {
            final String msg = intres.getLocalizedMessage("ra.invaliditydatenotallowed", issuerDn, certSerNo.toString(16));
            log.info(msg);
            throw new AlreadyRevokedException(msg);
        }
        // Check that unrevocation is not done on anything that can not be unrevoked
        if (!RevokedCertInfo.isRevoked(reason)) {
            if (revocationReason != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
                final String msg = intres.getLocalizedMessage("ra.errorunrevokenotonhold", issuerDn, certSerNo.toString(16));
                log.info(msg);
                throw new AlreadyRevokedException(msg);
            }
        } else {
            if (    revocationReason != RevokedCertInfo.NOT_REVOKED &&
                    // it should be possible to revoke a certificate on hold for good.
                    revocationReason != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD &&
                    // a valid certificate could have reason "REVOCATION_REASON_REMOVEFROMCRL" if it has been revoked in the past.
                    revocationReason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL ) {

                final CAData cadata = caSession.findById(certificateData.getIssuerDN().hashCode());
                final boolean allowedOnCa = cadata != null ? cadata.getCA().getCAInfo().isAllowChangingRevocationReason() : false;

                final boolean isX509 = cdw.getCertificate() instanceof X509Certificate;
                
                final boolean canChangeRevocationReason = RevokedCertInfo.canRevocationReasonBeChanged(reason, revocationDate, certificateData.getRevocationReason(), certificateData.getRevocationDate(), allowedOnCa, isX509);
                if (canChangeRevocationReason) {
                    // use the previous revocation date if a new one was not provided
                    if (revocationDate == null){
                        revocationDate = new Date(certificateData.getRevocationDate());
                    }
                    if (invalidityDate != null && !(cadata.getCA().getCAInfo().isAllowInvalidityDate())) {
                        invalidityDate = new Date(certificateData.getInvalidityDate());
                        final String msg = intres.getLocalizedMessage("ra.invaliditydatenotallowed");
                        log.info(msg);;
                        throw new AlreadyRevokedException(msg);
                    }
                }
                else if ((invalidityDate != null) && (reason == certificateData.getRevocationReason())) {
                    revocationDate = new Date(certificateData.getRevocationDate());
                    if (!cainfo.isAllowInvalidityDate()) {
                        final String msg = intres.getLocalizedMessage("ra.invaliditydatenotallowed");
                        log.info(msg);;
                        throw new AlreadyRevokedException(msg);
                    }
                }
                else if (!canChangeRevocationReason){
                    // Revocation reason cannot be changed, find out why and throw appropriate exception
                    if (!RevokedCertInfo.isDateOk(revocationDate, certificateData.getRevocationDate())) {
                        final String msg = intres.getLocalizedMessage("ra.invalidrevocationdate");
                        log.info(msg);
                        throw new AlreadyRevokedException(msg);
                    }
                    final String msg = intres.getLocalizedMessage("ra.errorrevocationexists", issuerDn, certSerNo.toString(16));
                    log.info(msg);
                    throw new AlreadyRevokedException(msg);
                }
            }
        }
        if (endEntityProfileId != EndEntityConstants.NO_END_ENTITY_PROFILE && certificateProfileId != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
            // We can only perform this check if we have a trail of what eep and cp was used..
            // Check if approvals is required.
            if(cainfo == null) {
                // If CA does not exist, the certificate is a bit "weird", but things can happen in reality and CAs can disappear
                // So the CA not existing should not prevent us from revoking the certificate.
                // It may however affect the possible Approvals, but we probably need to be able to do this in order to clean up a bad situation
                log.info("Trying to revoke a certificate issued by a CA, with ID "+caId+", that does not exist. IssuerDN='"+certificateData.getIssuerDN()+"'.");
            }
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.REVOCATION, cainfo,
                    certProfile);
            if (approvalProfile != null) {
                final RevocationApprovalRequest ar = new RevocationApprovalRequest(certSerNo, issuerDn, username, reason, authenticationToken, caId,
                        endEntityProfileId, approvalProfile, revocationDate, invalidityDate);
                if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKECERT)) {
                    final int requestId = approvalSession.addApprovalRequest(authenticationToken, ar);
                    throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalrevoke"), requestId);
                }
            }
        }
        // Finally find the publishers for the certificate profileId that we found
        Collection<Integer> publishers = new ArrayList<>(0);
        if (certificateProfile != null) {
            publishers = certificateProfile.getPublisherList();
            if (publishers == null || publishers.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No publishers defined for certificate with serial #" + certSerNo.toString(16) + " issued by " + issuerDn);
                }
            }
        } else {
            log.warn("No certificate profile for certificate with serial #" + certSerNo.toString(16) + " issued by " + issuerDn);
        }

        if(approvalRequestID != 0) {
            UserData userdata = endEntityAccessSession.findByUsername(username);
            ExtendedInformation ei = userdata.getExtendedInformation();
            if(ei == null) {
                ei = new ExtendedInformation();
            }
            ei.addRevokeEndEntityApprovalRequestId(approvalRequestID);
            userdata.setExtendedInformation(ei);
            userdata.setTimeModified((new Date()).getTime());
        }

        // Revoke certificate in database and all publishers
        try {
            revocationSession.revokeCertificate(authenticationToken, cdw, publishers, revocationDate!=null ? revocationDate : new Date(), invalidityDate, reason, certificateSubjectDN);
        } catch (CertificateRevokeException e) {
            final String msg = intres.getLocalizedMessage("ra.errorfindentitycert", issuerDn, certSerNo.toString(16));
            log.info(msg);
            throw new NoSuchEndEntityException(msg);
        }
        // In the case where this is an individual certificate revocation request, we still send a STATUS_REVOKED notification (since user state wont change)
        if (endEntityProfileId != EndEntityConstants.NO_END_ENTITY_PROFILE && endEntityInformationParam==null) {
            sendNotification(authenticationToken, endEntityInformation, EndEntityConstants.STATUS_REVOKED, 0, lastApprovingAdmin, cdw);
        }
        if (log.isTraceEnabled()) {
            log.trace("<revokeCert()");
        }
    }

    private void validateCertificateProfileExists(Integer certificateProfileIdParam) throws CertificateProfileDoesNotExistException {
        assert(certificateProfileIdParam != null);
        CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileIdParam);
        if (certificateProfile == null) {
            final String msg = intres.getLocalizedMessage("ra.errornocertificateprofile", certificateProfileIdParam);
            throw new CertificateProfileDoesNotExistException(msg);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean checkIfCertificateBelongToUser(BigInteger certificateSeNr, String issuerDn) {
        if (!WebConfiguration.getRequireAdminCertificateInDatabase()) {
            if (log.isTraceEnabled()) {
                log.trace("<checkIfCertificateBelongToUser Configured to ignore if cert belongs to user.");
            }
            return true;
        }
        final String username = certificateStoreSession.findUsernameByCertSerno(certificateSeNr, issuerDn);
        if (username != null) {
            if (endEntityAccessSession.findByUsername(username) == null) {
                final String msg = intres.getLocalizedMessage("ra.errorcertnouser", issuerDn, certificateSeNr.toString(16));
                log.info(msg);
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<EndEntityInformation> findUsers(List<Integer> caIds, long timeModified, int status) {
        StringBuilder queryString = new StringBuilder("SELECT a FROM UserData a WHERE (a.timeModified <=:timeModified) AND (a.status=:status)");
        if (!caIds.isEmpty()) {
            queryString.append(" AND (a.caId=:caId0");
            for (int i = 1; i < caIds.size(); i++) {
                queryString.append(" OR a.caId=:caId").append(i);
            }
            queryString.append(")");
        }
        if (log.isDebugEnabled()) {
            log.debug("Checking for " + caIds.size() + " CAs");
            log.debug("Generated query string: " + queryString);
        }
        TypedQuery<UserData> query = entityManager.createQuery(queryString.toString(), UserData.class);
        query.setParameter("timeModified", timeModified);
        query.setParameter("status", status);
        if (!caIds.isEmpty()) {
            for (int i = 0; i < caIds.size(); i++) {
                query.setParameter("caId" + i, caIds.get(i));
            }
        }
        final List<UserData> queryResult = query.getResultList();
        final List<EndEntityInformation> ret = new ArrayList<>(queryResult.size());
        for (UserData userData : queryResult) {
            ret.add(userData.toEndEntityInformation());
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean checkForCAId(int caId) {
        if (log.isTraceEnabled()) {
            log.trace(">checkForCAId()");
        }
        final long count = endEntityAccessSession.countByCaId(caId);
        if (count > 0) {
            if (log.isDebugEnabled()) {
                log.debug("CA exists in end entities: " + count);
            }
        }
        return count > 0;
    }

    private void sendNotification(final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation, final int newStatus,
            final int approvalRequestID, final AuthenticationToken lastApprovingAdmin, CertificateDataWrapper revokedCertificate) {
        if (endEntityInformation == null) {
            if (log.isDebugEnabled()) {
                log.debug("No UserData, no notification sent.");
            }
            return;
        }
        final String userEmail = endEntityInformation.getEmail();
        if (log.isTraceEnabled()) {
            log.trace(">sendNotification: user=" + endEntityInformation.getUsername() + ", email=" + userEmail);
        }
        // Make check if we should send notifications at all
        if (endEntityInformation.getType().contains(EndEntityTypes.SENDNOTIFICATION)) {
            final int endEntityProfileId = endEntityInformation.getEndEntityProfileId();
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
            final List<UserNotification> userNotifications = endEntityProfile.getUserNotifications();
            if (log.isDebugEnabled()) {
                log.debug("Number of user notifications: " + userNotifications.size());
            }
            String recipientEmail = userEmail; // Default value
            for (final UserNotification userNotification : userNotifications) {
                final Collection<Integer> events = userNotification.getNotificationEventsCollection();
                if (events.contains(newStatus)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Status is " + newStatus + ", notification sent for notificationevents: " + userNotification.getNotificationEvents());
                    }
                    try {
                        if (StringUtils.equals(userNotification.getNotificationRecipient(), UserNotification.RCPT_USER)) {
                            recipientEmail = userEmail;
                        } else if (StringUtils.contains(userNotification.getNotificationRecipient(), UserNotification.RCPT_CUSTOM)) {
                            // Just if this fail it will say that sending to user with email "custom" failed.
                            recipientEmail = "custom";
                            // Plug-in mechanism for retrieving custom notification email recipient addresses
                            if (userNotification.getNotificationRecipient().length() < 6) {
                                final String msg = intres.getLocalizedMessage("ra.errorcustomrcptshort", userNotification.getNotificationRecipient());
                                log.error(msg);
                            } else {
                                final String customClassName = userNotification.getNotificationRecipient().substring(7);
                                if (StringUtils.isNotEmpty(customClassName)) {
                                    ICustomNotificationRecipient plugin;
                                    try {
                                        plugin = (ICustomNotificationRecipient) Thread.currentThread()
                                                .getContextClassLoader().loadClass(customClassName).getDeclaredConstructor().newInstance();
                                    } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IllegalArgumentException
                                            | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                                        throw new MailException("Custom notification class " + customClassName + " could not be instansiated.", e);
                                    }
                                    recipientEmail = plugin.getRecipientEmails(endEntityInformation);
                                    if (StringUtils.isEmpty(recipientEmail)) {
                                        final String msg = intres.getLocalizedMessage("ra.errorcustomnoemail", userNotification.getNotificationRecipient());
                                        log.error(msg);
                                    } else {
                                        if (log.isDebugEnabled()) {
                                            log.debug("Custom notification recipient plugin returned email: " + recipientEmail);
                                        }
                                    }
                                } else {
                                    final String msg = intres.getLocalizedMessage("ra.errorcustomnoclasspath", userNotification.getNotificationRecipient());
                                    log.error(msg);
                                }
                            }
                        } else {
                            // Just a plain email address specified in the recipient field
                            recipientEmail = userNotification.getNotificationRecipient();
                        }
                        if (StringUtils.isEmpty(recipientEmail)) {
                            final String msg = intres.getLocalizedMessage("ra.errornotificationnoemail", endEntityInformation.getUsername());
                            throw new MailException(msg);
                        }
                        // Get the administrators DN from the admin certificate, if one exists
                        EndEntityInformation requestAdmin = null;
                        if (authenticationToken instanceof X509CertificateAuthenticationToken) {
                            final X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken) authenticationToken;
                            final X509Certificate adminCert = xtok.getCertificate();
                            final String username = certificateStoreSession.findUsernameByFingerprint(CertTools.getFingerprintAsString(adminCert));
                            if (username!=null) {
                                requestAdmin = endEntityAccessSession.findUser(username);
                            }
                        }
                        String lastApprovalAdminDN = null;
                        if (lastApprovingAdmin instanceof X509CertificateAuthenticationToken) {
                            final X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken) lastApprovingAdmin;
                            final X509Certificate adminCert = xtok.getCertificate();
                            lastApprovalAdminDN = CertTools.getSubjectDN(adminCert);
                        }

                        final UserNotificationParamGen paramGen = new UserNotificationParamGen(endEntityInformation, lastApprovalAdminDN, requestAdmin,
                                approvalRequestID, revokedCertificate);
                        // substitute any $ fields in the recipient and from fields
                        recipientEmail = paramGen.interpolate(recipientEmail);
                        final String fromemail = paramGen.interpolate(userNotification.getNotificationSender());
                        final String subject = paramGen.interpolate(userNotification.getNotificationSubject());
                        final String message = paramGen.interpolate(userNotification.getNotificationMessage());
                        MailSender.sendMailOrThrow(fromemail, Collections.singletonList(recipientEmail), MailSender.NO_CC, subject, message, MailSender.NO_ATTACHMENTS);
                        final String logmsg = intres.getLocalizedMessage("ra.sentnotification", endEntityInformation.getUsername(), recipientEmail);
                        log.info(logmsg);
                    } catch (MailException e) {
                        final String msg = intres.getLocalizedMessage("ra.errorsendnotification", endEntityInformation.getUsername(), recipientEmail);
                        log.error(msg, e);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Status is " + newStatus + ", no notification sent for notificationevents: " + userNotification.getNotificationEvents());
                    }
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Type ("+endEntityInformation.getType().getHexValue()+") does not contain EndEntityTypes.USER_SENDNOTIFICATION, no notification sent.");
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<sendNotification: user=" + endEntityInformation.getUsername() + ", email=" + userEmail);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsUser(String username) {
        // Selecting 1 column is optimal speed
        final javax.persistence.Query query = entityManager.createQuery("SELECT 1 FROM UserData a WHERE a.username = :username");
        query.setParameter("username", StringTools.trim(username));
        return !query.getResultList().isEmpty();
    }

    @Override
    public boolean prepareForKeyRecoveryInternal(
            AuthenticationToken authenticationToken, String username, int endEntityProfileId, Certificate certificate
    ) throws AuthorizationDeniedException, ApprovalException, CADoesntExistsException, WaitingForApprovalException {
        boolean ret;
        if (keyRecoverySession.authorizedToKeyRecover(authenticationToken, endEntityProfileId)) {
            keyRecoverySession.checkIfApprovalRequired(authenticationToken, EJBTools.wrap(certificate), username, endEntityProfileId, false);
            ret = true;
        } else {
            throw new AuthorizationDeniedException(authenticationToken + " not authorized to key recovery for end entity profile id " + endEntityProfileId);
        }
        try {
            final UserData data = endEntityAccessSession.findByUsername(username);
            if (data == null) {
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
                // This exception message is used to not leak information to the user
                final String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
                log.info(msg);
                throw new FinderException(msg);
            }
            endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, data.getCaId());
            setUserStatus(authenticationToken, data, EndEntityConstants.STATUS_KEYRECOVERY, 0, null);
        } catch (FinderException e) {
            ret = false;
            log.info("prepareForKeyRecovery: No such user: " + username);
        }
        return ret;
    }

    @Override
    public boolean prepareForKeyRecovery(
            AuthenticationToken authenticationToken, String username, int endEntityProfileId, Certificate certificate
    ) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, CADoesntExistsException {
        boolean ret;
        if (certificate == null) {
            ret = keyRecoverySession.markNewestAsRecoverable(authenticationToken, username, endEntityProfileId);
        } else {
            ret = keyRecoverySession.markAsRecoverable(authenticationToken, certificate, endEntityProfileId);
        }
        try {
            final UserData data = endEntityAccessSession.findByUsername(username);
            if (data == null) {
                log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
                // This exception message is used to not leak information to the user
                final String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
                log.info(msg);
                throw new FinderException(msg);
            }
            endEntityAuthenticationSession.assertAuthorizedToCA(authenticationToken, data.getCaId());
            setUserStatus(authenticationToken, data, EndEntityConstants.STATUS_KEYRECOVERY, 0, null);
        } catch (FinderException e) {
            ret = false;
            log.info("prepareForKeyRecovery: No such user: " + username);
        }
        return ret;
    }

    //
    // Private helper methods
    //

    /**
     * Resets the optional request counter of a user to the default value specified by the end entity profile. If the profile does not specify that
     * request counter should be used, the counter is removed.
     *
     * @param extendedInformation the ExtendedInformation object to modify
     * @return true if ExtendedInformation was changed (i.e. it should be saved), false otherwise
     */
    private boolean resetRequestCounter(
            final boolean onlyRemoveNoUpdate, final ExtendedInformation extendedInformation, final String username,
            final int endEntityProfileId
    ) {
        if (log.isTraceEnabled()) {
            log.trace(">resetRequestCounter(" + username + ", " + onlyRemoveNoUpdate + ")");
        }
        final EndEntityProfile prof = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
        String value = null;
        if (prof != null) {
            if (prof.isAllowedRequestsUsed()) {
                value = prof.getValue(EndEntityProfile.ALLOWEDREQUESTS, 0);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Can not fetch entity profile with ID " + endEntityProfileId);
            }
        }
        final String counter = extendedInformation.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        if (log.isDebugEnabled()) {
            log.debug("Old counter is: " + counter + ", new counter will be: " + value);
        }
        // If this end entity profile does not use ALLOWEDREQUESTS, this
        // value will be set to null
        // We only re-set this value if the COUNTER was used in the first
        // place, if never used, we will not fiddle with it
        boolean ret = false;
        if (counter != null) {
            if (!onlyRemoveNoUpdate || value == null) {
                extendedInformation.setCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER, value);
                if (log.isDebugEnabled()) {
                    log.debug("Re-set request counter for user '" + username + "' to:" + value);
                }
                ret = true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No re-setting counter because we should only remove");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Request counter not used, not re-setting it.");
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<resetRequestCounter(" + username + ", " + onlyRemoveNoUpdate + "): "+ret);
        }
        return ret;
    }
    
    /**
     * Checks the post-upgrade version, and reverts any incompatible changes.
     * This ensures compatibility with old EJBCA nodes running in a cluster.
     * @param extendedInformation ExtendedInformation object to modify, may be null.
     */
    private void ensureOldClusterNodeCompatibility(final ExtendedInformation extendedInformation) {
        if (extendedInformation == null) {
            return; // Noting to do
        }
        final GlobalUpgradeConfiguration upgradeConfig = (GlobalUpgradeConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        if (!upgradeConfig.isCustomCertificateValidityWithSecondsGranularity()) {
            // Downgrade to not use seconds granularity, for compatibility with versions prior to 7.2.0
            final String startTime = extendedInformation.getCertificateStartTime();
            if (startTime != null) {
                extendedInformation.setCertificateStartTime(ValidityDate.stripSecondsFromIso8601UtcDate(startTime));
            }
            final String endTime = extendedInformation.getCertificateEndTime();
            if (endTime != null) {
                extendedInformation.setCertificateEndTime(ValidityDate.stripSecondsFromIso8601UtcDate(endTime));
            }
        }
    }

    @Override
    public void finishUser(final EndEntityInformation data) throws NoSuchEndEntityException {
        if (log.isTraceEnabled()) {
            log.trace(">finishUser(" + data.getUsername() + ", hiddenpwd)");
        }
        try {

            // See if we are allowed for make more requests than this one. If not user status changed by decRequestCounter
            final int counter = decRequestCounter(data.getUsername());
            if (counter <= 0) {
                log.info(intres.getLocalizedMessage("authentication.statuschanged", data.getUsername()));
            }
            if (log.isTraceEnabled()) {
                log.trace("<finishUser("+data.getUsername()+", hiddenpwd)");
            }
        } catch (NoSuchEndEntityException e) {
            final String msg = intres.getLocalizedMessage("authentication.usernotfound", data.getUsername());
            log.info(msg);
            throw new NoSuchEndEntityException(e.getMessage());
        } catch (ApprovalException | WaitingForApprovalException e) {
            // Should never happen
            log.error("ApprovalException: ", e);
            throw new EJBException(e);
        }
    }

    // Logs a session event preserving constants:
    // EjbcaModuleTypes.RA - The module where the operation took place.
    // ServiceTypes.CORE - The service(application) that performed the operation.
    private void logAuditEvent(
            final EventType eventType,
            final EventStatus eventStatus,
            final AuthenticationToken authenticationToken, final Integer customId,
            final String searchDetail1, final String searchDetail2,
            final SecurityEventProperties securityEventProperties) {
        auditSession.log(
                eventType, eventStatus,
                EjbcaModuleTypes.RA, ServiceTypes.CORE,
                authenticationToken.toString(),
                String.valueOf(customId), searchDetail1, searchDetail2,
                securityEventProperties.toMap()
        );
    }
}
