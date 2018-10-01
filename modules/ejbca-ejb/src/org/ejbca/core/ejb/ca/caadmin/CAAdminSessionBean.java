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

package org.ejbca.core.ejb.ca.caadmin;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CANameChangeRenewalException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CvcCA;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.ocsp.exception.NotSupportedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.dn.DNFieldsUtil;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.NullCryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.keys.validation.Validator;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.util.CAIdTools;

/**
 * Manages CAs in EJBCA.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CAAdminSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CAAdminSessionBean implements CAAdminSessionLocal, CAAdminSessionRemote {

    private static final Logger log = Logger.getLogger(CAAdminSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
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
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal keyBindMgmtSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublishingCrlSessionLocal publishingCrlSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;
    @EJB
    private RevocationSessionLocal revocationSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private ServiceSessionLocal serviceSession;
    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;

    @Resource
    private SessionContext sessionContext;
    // Myself needs to be looked up in postConstruct
    private CAAdminSessionLocal caAdminSession;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PostConstruct
    public void postConstruct() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // We lookup the reference to our-self in PostConstruct, since we cannot inject this.
        // We can not inject ourself, JBoss will not start then therefore we use this to get a reference to this session bean
        // to call initializeCa we want to do it on the real bean in order to get the transaction setting (REQUIRES_NEW).
        caAdminSession = sessionContext.getBusinessObject(CAAdminSessionLocal.class);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void initializeAndUpgradeCAs() {
        final List<CAData> caDatas = caSession.findAll();
        // Sort CAs by name (to produce pretty table in log)
        Collections.sort(caDatas, new Comparator<CAData>() {
            @Override
            public int compare(final CAData arg0, final CAData arg1) {
                return arg0.getName().compareTo(arg1.getName());
            }
        });
        // Figure out the longest CA name (to produce pretty table in log)
        int maxNameLenght = 0;
        for (final CAData caData : caDatas) {
            if (caData.getName().length() > maxNameLenght) {
                maxNameLenght = caData.getName().length();
            }
        }
        for (final CAData caData : caDatas) {
            final String caName = caData.getName();
            try {
                caAdminSession.initializeAndUpgradeCA(caData.getCaId());
                final String expires = ValidityDate.formatAsISO8601ServerTZ(caData.getExpireTime(), ValidityDate.TIMEZONE_SERVER);
                log.info("Initialized CA: " + String.format("%-" + maxNameLenght + "s", caName) + " with expire time: " + expires);
            } catch (CADoesntExistsException e) {
                log.error("CADoesntExistsException trying to load CA with name: " + caName, e);
            } catch (Throwable e) {
                log.error("Exception trying to load CA, possible upgrade not performed: " + caName, e);
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void initializeAndUpgradeCA(Integer caid) throws CADoesntExistsException {
        caSession.getCAInfoInternal(caid, null, false);
    }

    @Override
    public void initializeCa(final AuthenticationToken authenticationToken, final CAInfo caInfo)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidAlgorithmException {

        if (caInfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
            throw new IllegalArgumentException("CA Status was not CA_UNINITIALIZED (" + CAConstants.CA_UNINITIALIZED + ")");
        }
        //Find the intended status
        caInfo.setStatus(getCaStatus(caInfo));

        // Since it's acceptable that SubjectDN (and CAId) changes, in initializing we'll simply kill the old uninitialized CA and then recreate it if anything has changed.
        int calculatedCAId = CertTools.stringToBCDNString(caInfo.getSubjectDN()).hashCode();
        int currentCAId = caInfo.getCAId();
        if (calculatedCAId != currentCAId) {
            caSession.removeCA(authenticationToken, currentCAId);
            caInfo.setCAId(calculatedCAId);
            updateCAIds(authenticationToken, currentCAId, calculatedCAId, caInfo.getSubjectDN());
            CAIdTools.rebuildExtendedServices(caInfo);
            try {
                createCA(authenticationToken, caInfo);
            } catch (CAExistsException e) {
                throw new IllegalStateException(e);
            }
        } else {
            // No Subject DN change
            CAToken caToken = caInfo.getCAToken();
            CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(caInfo.getCertificateProfileId());
            CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(caToken.getCryptoTokenId());
            // See if CA token is OK before generating keys
            try {
                cryptoToken.testKeyPair(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
            } catch (InvalidKeyException e1) {
                throw new IllegalStateException("The CA's test key alias points to an invalid key.", e1);
            }

            try {
                mergeCertificatePoliciesFromCAAndProfile(caInfo, certprofile);
                caSession.editCA(authenticationToken, caInfo);
                CA ca = caSession.getCA(authenticationToken, caInfo.getCAId());
                ca.updateUninitializedCA(caInfo);
                ca.setCAToken(caToken);
                ca.setCAInfo(caInfo);
                //Store the chain and new status.
                caSession.editCA(authenticationToken, ca, false);

                // Finish up and create certificate chain, CRL, etc.
                finalizeInitializedCA(authenticationToken, ca, caInfo, cryptoToken, certprofile);
            } catch (CADoesntExistsException e) {
                // getCAInfo should have thrown this exception already
                throw new IllegalStateException(e);
            }
        }

        if (caInfo.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA) {
            try {
                renewAndRevokeCmsCertificate(authenticationToken, caInfo.getCAId());
            } catch (CADoesntExistsException e) {
                // getCAInfo should have thrown this exception already
                throw new IllegalStateException(e);
            } catch (CAOfflineException e) {
                // This should not happen.
                // The user can ignore these errors if he/she does not use CMS
                log.error("Failed to renew extended service (CMS) certificates for ca '" + caInfo.getName() + "'.", e);
            } catch (CertificateRevokeException e) {
                // ditto
                log.error("Failed to renew extended service (CMS) certificates for ca '" + caInfo.getName() + "'.", e);
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void updateCAIds(AuthenticationToken authenticationToken, int fromId, int toId, String toDN) throws AuthorizationDeniedException {
        log.info("Updating CAIds in relations from " + fromId + " to " + toId + "\n");

        // Update Certificate Profiles
        final Map<Integer, String> certProfiles = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (Integer certProfId : certProfiles.keySet()) {
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfId);
            if (CAIdTools.updateCAIds(certProfile, fromId, toId, toDN)) {
                String name = certProfiles.get(certProfId);
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in Certificate Profile " + name);
                }
                certificateProfileSession.changeCertificateProfile(authenticationToken, name, certProfile);
            }
        }

        // Update End-Entity Profiles
        final Map<Integer, String> endEntityProfiles = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        for (Integer endEntityProfId : endEntityProfiles.keySet()) {
            final EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfId);
            if (CAIdTools.updateCAIds(endEntityProfile, fromId, toId, toDN)) {
                String name = endEntityProfiles.get(endEntityProfId);
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in End Entity Profile " + name);
                }
                try {
                    endEntityProfileSession.changeEndEntityProfile(authenticationToken, name, endEntityProfile);
                } catch (EndEntityProfileNotFoundException e) {
                    log.error("End-entity profile " + name + " could no longer be found", e);
                }
            }
        }

        // Update Approval Profiles
        final Map<Integer, String> approvalProfiles = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (int appProfId : approvalProfiles.keySet()) {
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(appProfId);
            if (approvalProfile.updateCAIds(fromId, toId, toDN)) {
                String name = approvalProfile.getProfileName();
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in Approval Profile " + name);
                }
                approvalProfileSession.changeApprovalProfile(authenticationToken, approvalProfile);
            }
        }

        // Update End-Entities
        final Collection<EndEntityInformation> endEntities = endEntityAccessSession.findAllUsersByCaIdNoAuth(fromId);
        for (EndEntityInformation endEntityInfo : endEntities) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Id of End Entity " + endEntityInfo.getUsername());
                }
                endEntityManagementSession.updateCAId(authenticationToken, endEntityInfo.getUsername(), toId);
            } catch (NoSuchEndEntityException e) {
                log.error("End entity " + endEntityInfo.getUsername() + " could no longer be found", e);
            }
        }

        // Update Data Sources
        final Map<Integer, String> dataSources = userDataSourceSession.getUserDataSourceIdToNameMap(authenticationToken);
        for (Integer dataSourceId : dataSources.keySet()) {
            final BaseUserDataSource dataSource = userDataSourceSession.getUserDataSource(authenticationToken, dataSourceId);
            if (CAIdTools.updateCAIds(dataSource, fromId, toId, toDN)) {
                String name = dataSources.get(dataSourceId);
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in User Data Source " + name);
                }
                userDataSourceSession.changeUserDataSource(authenticationToken, name, dataSource);
            }
        }

        // Update Services
        final Map<Integer, String> services = serviceSession.getServiceIdToNameMap();
        for (String serviceName : services.values()) {
            final ServiceConfiguration serviceConf = serviceSession.getService(serviceName);
            if (CAIdTools.updateCAIds(serviceConf, fromId, toId, toDN)) {
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in Service " + serviceName);
                }
                serviceSession.changeService(authenticationToken, serviceName, serviceConf, false);
            }
        }

        // Update Internal Key Bindings
        Map<String, Map<String, DynamicUiProperty<?>>> keyBindTypes = keyBindMgmtSession.getAvailableTypesAndProperties();
        Map<String, List<Integer>> typesKeybindings = new HashMap<>();
        for (String type : keyBindTypes.keySet()) {
            typesKeybindings.put(type, keyBindMgmtSession.getInternalKeyBindingIds(authenticationToken, type));
        }
        for (Map.Entry<String, List<Integer>> entry : typesKeybindings.entrySet()) {
            final List<Integer> keybindIds = entry.getValue();
            for (int keybindId : keybindIds) {
                final InternalKeyBinding keybind = keyBindMgmtSession.getInternalKeyBinding(authenticationToken, keybindId);
                if (CAIdTools.updateCAIds(keybind, fromId, toId, toDN)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Changing CA Ids in Internal Key Binding " + keybind.getName());
                    }
                    try {
                        keyBindMgmtSession.persistInternalKeyBinding(authenticationToken, keybind);
                    } catch (InternalKeyBindingNameInUseException e) {
                        // Should never happen
                        log.error("Name existed when trying to update keybinding", e);
                    }
                }
            }
        }

        // Update System Configuration
        GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (globalConfig != null) {
            if (CAIdTools.updateCAIds(globalConfig, fromId, toId, toDN)) {
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in System Configuration");
                }
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfig);
            }
        }

        // Update CMP Configuration
        // Only "Default CA" contains a reference to the Subject DN. All other fields reference the CAs by CA name.
        CmpConfiguration cmpConfig = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        if (cmpConfig != null) {
            if (CAIdTools.updateCAIds(cmpConfig, fromId, toId, toDN)) {
                if (log.isDebugEnabled()) {
                    log.debug("Changing CA Ids in CMP configuration");
                }
                globalConfigurationSession.saveConfiguration(authenticationToken, cmpConfig);
            }
        }

        // Update Roles
        roleSession.updateCaId(fromId, toId, false, true);
        log.debug("Done updating CA Ids");
        final String detailsMsg = intres.getLocalizedMessage("caadmin.updatedcaid", fromId, toId, toDN);
        auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                String.valueOf(toId), null, null, detailsMsg);
    }

    @Override
    public void renewAndRevokeCmsCertificate(final AuthenticationToken admin, int caid)
            throws AuthorizationDeniedException, CADoesntExistsException, CAOfflineException, CertificateRevokeException {
        CAInfo cainfo = caSession.getCAInfo(admin, caid);
        for (final ExtendedCAServiceInfo next : cainfo.getExtendedCAServiceInfos()) {
            if (next instanceof CmsCAServiceInfo) {
                List<Certificate> cmscerts = ((CmsCAServiceInfo) next).getCertificatePath();
                if (cmscerts != null) {
                    X509Certificate cmscert = (X509Certificate) cmscerts.get(0);
                    final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(CertTools.getFingerprintAsString(cmscert));
                    revocationSession.revokeCertificate(admin, cdw, cainfo.getCRLPublishers(), new Date(),
                            RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, cainfo.getSubjectDN());
                }
                initExternalCAService(admin, caid, next);
            }
        }
    }

    private CA createCAObject(CAInfo cainfo, CAToken catoken, CertificateProfile certprofile) throws InvalidAlgorithmException {
        CA ca = null;
        // X509 CA is the most normal type of CA
        if (cainfo instanceof X509CAInfo) {
            log.info("Creating an X509 CA: " + cainfo.getName());
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            // Create X509CA
            ca = new X509CA(x509cainfo);
            ca.setCAToken(catoken);
            // Set certificate policies in profile object
            mergeCertificatePoliciesFromCAAndProfile(x509cainfo, certprofile);
        } else {
            // CVC CA is a special type of CA for EAC electronic passports
            log.info("Creating a CVC CA: " + cainfo.getName());
            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
            // Create CVCCA
            ca = CvcCA.getInstance(cvccainfo);
            ca.setCAToken(catoken);
        }
        return ca;
    }

    /** When creating, or renewing a CA we will merge the certificate policies from the CAInfo and the CertificateProfile.
     * Since  Certificate generation uses the CertificateProfile, we merge them into the CertificateProfile object.
     *
     * @param cainfo cainfo that may contain certificate policies, or not
     * @param certprofile CertificateProfile that may contain certificate policies or not, this object is modified
     */
    private void mergeCertificatePoliciesFromCAAndProfile(CAInfo cainfo, CertificateProfile certprofile) {
        if (cainfo instanceof X509CAInfo) {
            X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            // getCertificateProfile
            if ((x509cainfo.getPolicies() != null) && (x509cainfo.getPolicies().size() > 0)) {
                List<CertificatePolicy> policies = certprofile.getCertificatePolicies();
                policies.addAll(x509cainfo.getPolicies());
                // If the profile did not say to use the extensions before, add it.
                certprofile.setUseCertificatePolicies(true);
            }
        }
        // If not an X509CA, we will not do anything, because there are only certificate policies for X509CAs
    }

    @Override
    public void createCA(final AuthenticationToken admin, final CAInfo cainfo)
            throws AuthorizationDeniedException, CAExistsException, CryptoTokenOfflineException, InvalidAlgorithmException {
        if (log.isTraceEnabled()) {
            log.trace(">createCA: " + cainfo.getName());
        }
        final int caid = cainfo.getCAId();
        // Check that administrator has superadminstrator rights.
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", cainfo.getName());
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Check that CA doesn't already exists
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.wrongcaid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        if (caSession.findById(Integer.valueOf(caid)) != null) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        if (caSession.findByName(cainfo.getName()) != null) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, detailsMsg);
            throw new CAExistsException(detailsMsg);
        }
        // Check if we are creating a CVC CA, and in case we have a unique (issuerDN,serialNumber) index in the database, then fail fast.
        if ((cainfo.getCAType() == CAInfo.CATYPE_CVC) && certificateStoreSession.isUniqueCertificateSerialNumberIndex()) {
            throw new IllegalArgumentException(
                    "Not possible to create CVC CA when there is a unique (issuerDN, serialNumber) index in the database.");
        }
        // Create CAToken
        final CAToken caToken = cainfo.getCAToken();
        int cryptoTokenId = caToken.getCryptoTokenId();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
        // The certificate profile used for the CAs certificate
        CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
        // Create CA
        CA ca = createCAObject(cainfo, caToken, certprofile);
        if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
            // See if CA token is OK before storing CA, but skip if no keys can be guaranteed to exist.
            try {
                cryptoToken.testKeyPair(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
            } catch (InvalidKeyException e1) {
                throw new RuntimeException("The CA's test key alias points to an invalid key.", e1);
            }
        }
        // Store CA in database, so we can generate keys using the ca token session.
        try {
            caSession.addCA(admin, ca);
        } catch (CAExistsException e) {
            String msg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, details);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        }

        // Finish up and create certificate chain etc.
        // Both code paths will audit log.
        if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
            finalizeInitializedCA(admin, ca, cainfo, cryptoToken, certprofile);
        } else {
            // Special handling for uninitialized CAs
            ca.setCertificateChain(new ArrayList<Certificate>());
            ca.setStatus(CAConstants.CA_UNINITIALIZED);

            if (log.isDebugEnabled()) {
                log.debug("Setting CA status to: " + CAConstants.CA_UNINITIALIZED);
            }
            try {
                caSession.editCA(admin, ca, true);
            } catch (CADoesntExistsException e) {
                final String detailsMsg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
                auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        String.valueOf(caid), null, null, detailsMsg);
                throw new EJBException(e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<createCA: " + cainfo.getName());
        }
    }

    /**
     * The final steps of creating a CA, which are not performed for uninitialized CAs until
     * they are initialized.
     *
     * It creates a certificate chain and publishes certificate, services, CRLs, etc.
     * This method also performs audit logging.
     */
    private void finalizeInitializedCA(final AuthenticationToken admin, final CA ca, final CAInfo cainfo, final CryptoToken cryptoToken,
            final CertificateProfile certprofile) throws CryptoTokenOfflineException, AuthorizationDeniedException {

        if (cainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
            throw new IllegalStateException("This method should never be called on uninitialized CAs");
        }

        final int caid = cainfo.getCAId();
        List<Certificate> certificatechain = createCertificateChain(admin, ca, cryptoToken, certprofile);
        int castatus = getCaStatus(cainfo);
        ca.setCertificateChain(certificatechain);
        if (log.isDebugEnabled()) {
            log.debug("Setting CA status to: " + castatus);
        }
        ca.setStatus(castatus);
        try {
            caSession.editCA(admin, ca, true);
        } catch (CADoesntExistsException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, detailsMsg);
            throw new EJBException(e);
        }
        // Publish CA certificates if CA is initialized
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
        switch (castatus) {
        case CAConstants.CA_ACTIVE:
            // activate External CA Services
            activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
            try {
                caSession.editCA(admin, ca, false); // store any activates CA services
                // create initial CRLs
                publishingCrlSession.forceCRL(admin, ca.getCAId());
                publishingCrlSession.forceDeltaCRL(admin, ca.getCAId());
            } catch (CADoesntExistsException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        String.valueOf(caid), null, null, details);
                throw new EJBException(e);
            } catch (CAOfflineException e) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        String.valueOf(caid), null, null, details);
                throw new EJBException(e);
            }
            break;
        default:
            log.error("CA status not active when creating CA, extended services not created. CA status: " + castatus);
            break;
        }

        // Update local OCSP's CA certificate cache
        certificateStoreSession.reloadCaCertificateCache();
    }

    private int getCaStatus(CAInfo cainfo) {
        int castatus = CAConstants.CA_OFFLINE;
        if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
            castatus = CAConstants.CA_ACTIVE;
        } else if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
            // set status to waiting certificate response.
            castatus = CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
        } else if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            castatus = CAConstants.CA_ACTIVE;
        }
        return castatus;
    }

    private List<Certificate> createCertificateChain(AuthenticationToken authenticationToken, CA ca, CryptoToken cryptoToken,
            CertificateProfile certprofile) throws CryptoTokenOfflineException {
        final CAInfo cainfo = ca.getCAInfo();
        final CAToken caToken = cainfo.getCAToken();
        List<Certificate> certificatechain = null;
        final String sequence = caToken.getKeySequence(); // get from CAtoken to make sure it is fresh
        final String aliasCertSign = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        int caid = cainfo.getCAId();
        final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
            try {
                // create selfsigned certificate
                Certificate cacertificate = null;
                if (log.isDebugEnabled()) {
                    log.debug("CAAdminSessionBean : " + cainfo.getSubjectDN());
                }
                EndEntityInformation cadata = makeEndEntityInformation(cainfo);
                cacertificate = ca.generateCertificate(cryptoToken, cadata, cryptoToken.getPublicKey(aliasCertSign), -1, null,
                        cainfo.getEncodedValidity(), certprofile, sequence, cceConfig);
                if (log.isDebugEnabled()) {
                    log.debug("CAAdminSessionBean : " + CertTools.getSubjectDN(cacertificate));
                }
                // Build Certificate Chain
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                // set status to active

            } catch (CryptoTokenOfflineException e) {
                final String detailsMsg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, detailsMsg);
                sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", fe.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, details);
                throw new EJBException(fe);
            }
        } else if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
            certificatechain = new ArrayList<Certificate>();

        } else if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            // Create CA signed by other internal CA.
            try {
                final CA signca = caSession.getCAForEdit(authenticationToken, Integer.valueOf(cainfo.getSignedBy()));
                // Check that the signer is valid
                assertSignerValidity(authenticationToken, signca);
                // Create CA certificate
                EndEntityInformation cadata = makeEndEntityInformation(cainfo);
                CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());
                final Certificate cacertificate = signca.generateCertificate(signCryptoToken, cadata, cryptoToken.getPublicKey(aliasCertSign), -1,
                        null, cainfo.getEncodedValidity(), certprofile, sequence, cceConfig);
                // Build Certificate Chain
                List<Certificate> rootcachain = signca.getCertificateChain();
                certificatechain = new ArrayList<Certificate>();
                certificatechain.add(cacertificate);
                certificatechain.addAll(rootcachain);
                // set status to active

            } catch (CryptoTokenOfflineException e) {
                final String detailsMsg = intres.getLocalizedMessage("error.catokenoffline", cainfo.getName());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, detailsMsg);
                sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
                throw e;
            } catch (Exception fe) {
                String msg = intres.getLocalizedMessage("caadmin.errorcreateca", cainfo.getName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", fe.getMessage());
                auditSession.log(EventTypes.CA_CREATION, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, details);
                throw new EJBException(fe);
            }
        }
        return certificatechain;

    }

    private EndEntityInformation makeEndEntityInformation(final CAInfo cainfo) {
        String caAltName = null;
        ExtendedInformation extendedinfo = null;
        if (cainfo instanceof X509CAInfo) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            caAltName = x509cainfo.getSubjectAltName();
            extendedinfo = new ExtendedInformation();
            extendedinfo.setNameConstraintsPermitted(x509cainfo.getNameConstraintsPermitted());
            extendedinfo.setNameConstraintsExcluded(x509cainfo.getNameConstraintsExcluded());
        }

        return new EndEntityInformation("nobody", cainfo.getSubjectDN(), cainfo.getSubjectDN().hashCode(), caAltName, null, 0,
                new EndEntityType(EndEntityTypes.INVALID), 0, cainfo.getCertificateProfileId(), null, null, 0, 0, extendedinfo);
    }

    @Override
    public void editCA(AuthenticationToken admin, CAInfo cainfo) throws AuthorizationDeniedException {
        boolean cmsrenewcert = false;
        final int caid = cainfo.getCAId();

        // In uninitialized CAs, the Subject DN might change, and then
        // we need to update the CA ID as well.
        if (cainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
            int calculatedCAId = CertTools.stringToBCDNString(cainfo.getSubjectDN()).hashCode();
            int currentCAId = cainfo.getCAId();
            if (calculatedCAId != currentCAId) {
                caSession.removeCA(admin, currentCAId);
                cainfo.setCAId(calculatedCAId);
                updateCAIds(admin, currentCAId, calculatedCAId, cainfo.getSubjectDN());
                CAIdTools.rebuildExtendedServices(cainfo);
                try {
                    createCA(admin, cainfo);
                } catch (CAExistsException e) {
                    throw new IllegalStateException(e);
                } catch (CryptoTokenOfflineException e) {
                    throw new IllegalStateException(e);
                } catch (InvalidAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }
        }

        // Check if extended service certificates are about to be renewed.
        if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
            final Collection<ExtendedCAServiceInfo> extendedCAServiceInfos = cainfo.getExtendedCAServiceInfos();
            if (extendedCAServiceInfos != null) {
                for (final ExtendedCAServiceInfo extendedCAServiceInfo : extendedCAServiceInfos) {
                    if (extendedCAServiceInfo instanceof CmsCAServiceInfo) {
                        final BaseSigningCAServiceInfo signingInfo = (BaseSigningCAServiceInfo) extendedCAServiceInfo;
                        cmsrenewcert = signingInfo.getRenewFlag()
                                || (signingInfo.getCertificatePath() == null && signingInfo.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE);
                    }
                }
            }
        }

        // Get CA from database
        try {
            caSession.editCA(admin, cainfo);
            CA ca = caSession.getCA(admin, cainfo.getCAId());
            if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
                // No OCSP Certificate exists that can be renewed.
                if (cmsrenewcert) {
                    CmsCAServiceInfo info = (CmsCAServiceInfo) ca.getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE);
                    if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
                        final ArrayList<Certificate> cmscertificate = new ArrayList<Certificate>();
                        cmscertificate.add(info.getCertificatePath().get(0));
                        // Publish the extended service certificate, but only for active services
                        publishCACertificate(admin, cmscertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                    }
                }
            }
            // Log Action was done by caSession
        } catch (AuthorizationDeniedException e) {
            String msg = intres.getLocalizedMessage("caadmin.erroreditca", cainfo.getName());
            log.error(msg, e);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, details);
            throw e;
        } catch (CADoesntExistsException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] makeRequest(AuthenticationToken authenticationToken, int caid, Collection<?> certChain, String nextSignKeyAlias)
            throws AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">makeRequest: " + caid + ", certChain=" + certChain + ", nextSignKeyAlias=" + nextSignKeyAlias);
        }
        byte[] returnval = null;
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CARENEW.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        try {
            final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
            final CA ca = caSession.getCAForEdit(authenticationToken, caid);
            final List<Certificate> chain = new ArrayList<Certificate>();
            if (certChain != null && certChain.size() > 0) {
                chain.addAll(CertTools.createCertChain(certChain));
                log.debug("Setting request certificate chain of size: " + chain.size());
                ca.setRequestCertificateChain(chain);
            }
            // AR+ patch to make SPOC independent of external CVCA certificates for automatic renewals
            // i.e. if we don't pass a CA certificate as parameter we try to find a suitable CA certificate in the database, among existing CAs
            // (can be a simple imported CA-certificate of external CA)
            if (chain.isEmpty() && ca.getCAType() == CAInfo.CATYPE_CVC && ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA
                    && ca.getStatus() == CAConstants.CA_ACTIVE) {
                final CardVerifiableCertificate dvcert = (CardVerifiableCertificate) ca.getCACertificate();
                final String ca_ref = dvcert.getCVCertificate().getCertificateBody().getAuthorityReference().getConcatenated();
                log.debug("DV renewal missing CVCA cert, try finding CA for:" + ca_ref);
                for (final Integer availableCaId : caSession.getAuthorizedCaIds(authenticationToken)) {
                    final CA cvca = caSession.getCA(authenticationToken, availableCaId);
                    if (cvca.getCAType() == CAInfo.CATYPE_CVC && cvca.getSignedBy() == CAInfo.SELFSIGNED) {
                        final CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cvca.getCACertificate();
                        if (ca_ref.equals(cvccert.getCVCertificate().getCertificateBody().getHolderReference().getConcatenated())) {
                            log.debug("Added missing CVCA to rewnewal request: " + cvca.getName());
                            chain.add(cvccert);
                            break;
                        }
                    }
                }
                if (chain.isEmpty()) {
                    log.info("Failed finding suitable CVCA, forgot to import it?");
                }
            }
            // AR-

            // Generate new certificate signing request.
            final CAToken caToken = ca.getCAToken();
            final String signatureAlgorithm = caToken.getSignatureAlgorithm();
            if (log.isDebugEnabled()) {
                log.debug("Using signing algorithm: " + signatureAlgorithm + " for the CSR.");
            }
            final Properties oldprop = caToken.getProperties();
            final String oldsequence = caToken.getKeySequence();
            // If no alias is supplied we use the CAs current signature key and the KeySequence to generate a new one
            if (nextSignKeyAlias == null || nextSignKeyAlias.length() == 0) {
                nextSignKeyAlias = caToken.generateNextSignKeyAlias();
            }
            caToken.setNextCertSignKey(nextSignKeyAlias);
            final int cryptoTokenId = caToken.getCryptoTokenId();
            try {
                // Test if key already exists
                cryptoTokenManagementSession.testKeyPair(authenticationToken, cryptoTokenId, nextSignKeyAlias);
            } catch (Exception e) {
                try {
                    final String currentSignKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                    cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentSignKeyAlias,
                            nextSignKeyAlias);
                    // Audit log CA key generation
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", intres.getLocalizedMessage("catoken.generatedkeys", caid, true, false));
                    details.put("oldproperties", oldprop);
                    details.put("oldsequence", oldsequence);
                    details.put("properties", caToken.getProperties());
                    details.put("sequence", caToken.getKeySequence());
                    auditSession.log(EventTypes.CA_KEYGEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                            String.valueOf(caid), null, null, details);
                } catch (AuthorizationDeniedException | CryptoTokenOfflineException e2) {
                    throw e2;
                } catch (Exception e2) {
                    throw new RuntimeException(e2);
                }
            }
            ca.setCAToken(caToken);
            // The CA certificate signing this request is the first in the certificate chain
            final Certificate caCert = chain.size() == 0 ? null : chain.get(0);
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId);
            final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
            byte[] request = ca.createRequest(cryptoToken, null, signatureAlgorithm, caCert, CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT, certificateProfile, cceConfig);
            if (ca.getCAType() == CAInfo.CATYPE_CVC) {
                /*
                 * If this is a CVC CA renewal request, we need to sign it to make an authenticated
                 * request. The CVC CAs current signing certificate will always be the right one,
                 * because it is the "previous" signing certificate until we have imported a new
                 * one as response to the request we create here.
                 */
                // Sign the request with the current sign key making it an CVCAuthenticatedRequest
                final byte[] authCertSignRequest = ca.createAuthCertSignRequest(cryptoToken, request);
                if (authCertSignRequest != null) {
                    returnval = authCertSignRequest;
                } else {
                    // This is expected if we try to generate another CSR from a CA which has not yet received a response.
                    log.debug("Unable to create authorization signature on CSR. Returning a regular request.");
                    returnval = request;
                }
            } else {
                returnval = request;
            }
            caSession.editCA(authenticationToken, ca, true);
            // Log information about the event
            final String detailsMsg = intres.getLocalizedMessage("caadmin.certreqcreated", ca.getName(), Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CertPathValidatorException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (CryptoTokenOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<makeRequest: " + caid);
        }
        return returnval;
    }

    @Override
    public byte[] createAuthCertSignRequest(AuthenticationToken authenticationToken, int caid, byte[] certSignRequest)
            throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertreq", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        final CA signedbyCA = caSession.getCA(authenticationToken, caid);
        final String caname = signedbyCA.getName();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(signedbyCA.getCAToken().getCryptoTokenId());
        final byte[] returnval = signedbyCA.createAuthCertSignRequest(cryptoToken, certSignRequest);
        final String detailsMsg = intres.getLocalizedMessage("caadmin.certreqsigned", caname);
        auditSession.log(EjbcaEventTypes.CA_SIGNREQUEST, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                String.valueOf(caid), null, null, detailsMsg);
        return returnval;
    }

    @Override
    public void receiveResponse(AuthenticationToken authenticationToken, int caid, ResponseMessage responsemessage, Collection<?> cachain,
            String nextKeyAlias) throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException {
        receiveResponse(authenticationToken, caid, responsemessage, cachain, nextKeyAlias, false);
    }

    @Override
    public void receiveResponse(AuthenticationToken authenticationToken, int caid, ResponseMessage responsemessage, Collection<?> cachain,
            String nextKeyAlias, boolean futureRollover)
            throws AuthorizationDeniedException, CertPathValidatorException, EjbcaException, CesecoreException {
        if (log.isTraceEnabled()) {
            log.trace(">receiveResponse: " + caid);
        }
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CARENEW.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        }
        try {
            final CA ca = caSession.getCAForEdit(authenticationToken, caid);
            if (ca == null) {
                throw new CADoesntExistsException("CA with ID " + caid + " does not exist.");
            } else {
                if (!(responsemessage instanceof X509ResponseMessage)) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcertrespillegalmsg",
                            responsemessage != null ? responsemessage.getClass().getName() : "null");
                    log.info(msg);
                    throw new EjbcaException(msg);
                }
                final Certificate cacert = ((X509ResponseMessage) responsemessage).getCertificate();
                // Receiving a certificate for an internal CA will transform it into an externally signed CA
                if (ca.getSignedBy() != CAInfo.SIGNEDBYEXTERNALCA) {
                    ca.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
                }
                // Check that CA DN is equal to the certificate response.
                if (!CertTools.getSubjectDN(cacert).equals(CertTools.stringToBCDNString(ca.getSubjectDN()))) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcertrespwrongdn", CertTools.getSubjectDN(cacert), ca.getSubjectDN());
                    log.info(msg);
                    throw new EjbcaException(msg);
                }
                List<Certificate> tmpchain = new ArrayList<Certificate>();
                tmpchain.add(cacert);

                Date verifydate = new Date();
                if (futureRollover) {
                    log.debug("Certificate will only be used for key rollover until it becomes valid.");

                    final Date rolloverdate = CertTools.getNotBefore(cacert);
                    if (rolloverdate.after(new Date())) {
                        verifydate = rolloverdate;
                    } else {
                        // Validate using today's date, in case something has expired
                        log.info("Expected to receive a certificate to use in the future, but received an already valid certificate.");
                    }
                }

                Collection<Certificate> reqchain = null;
                if (cachain != null && cachain.size() > 0) {
                    //  1. If we have a chain given as parameter, we will use that.
                    reqchain = CertTools.createCertChain(cachain, verifydate);
                    if (log.isDebugEnabled()) {
                        log.debug("Using CA certificate chain from parameter of size: " + reqchain.size());
                    }
                } else {
                    // 2. If no parameter is given we assume that the request chain was stored when the request was created.
                    reqchain = ca.getRequestCertificateChain();
                    if (reqchain == null) {
                        // 3. Lastly, if that failed we'll check if the certificate chain in it's entirety already exists in the database.
                        reqchain = new ArrayList<Certificate>();
                        Certificate issuer = certificateStoreSession.findLatestX509CertificateBySubject(CertTools.getIssuerDN(cacert));
                        if (issuer != null) {
                            reqchain.add(issuer);
                            while (!CertTools.isSelfSigned(issuer)) {
                                issuer = certificateStoreSession.findLatestX509CertificateBySubject(CertTools.getIssuerDN(issuer));
                                if (issuer != null) {
                                    reqchain.add(issuer);
                                } else {
                                    String msg = intres.getLocalizedMessage("caadmin.errorincompleterequestchain", caid, ca.getSubjectDN());
                                    log.info(msg);
                                    throw new CertPathValidatorException(msg);
                                }
                            }
                        }
                        if (reqchain.size() == 0) {
                            String msg = intres.getLocalizedMessage("caadmin.errornorequestchain", caid, ca.getSubjectDN());
                            log.info(msg);
                            throw new CertPathValidatorException(msg);
                        }

                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Using pre-stored CA certificate chain.");
                        }
                    }
                }

                if (log.isDebugEnabled()) {
                    log.debug("Picked up request certificate chain of size: " + reqchain.size());
                }
                tmpchain.addAll(reqchain);
                final List<Certificate> chain = CertTools.createCertChain(tmpchain, verifydate);
                if (log.isDebugEnabled()) {
                    log.debug("Storing certificate chain of size: " + chain.size());
                }
                // Before importing the certificate we want to make sure that the public key matches the CAs private key
                PublicKey caCertPublicKey = cacert.getPublicKey();
                // If it is a DV certificate signed by a CVCA, enrich the public key for EC parameters from the CVCA's certificate
                if (StringUtils.equals(cacert.getType(), "CVC")) {
                    if (caCertPublicKey.getAlgorithm().equals("ECDSA")) {
                        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cacert;
                        try {
                            if (cvccert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getAuthRole()
                                    .isDV()) {
                                log.debug("Enriching DV public key with EC parameters from CVCA");
                                Certificate cvcacert = reqchain.iterator().next();
                                caCertPublicKey = KeyTools.getECPublicKeyWithParams(caCertPublicKey, cvcacert.getPublicKey());
                            }
                        } catch (InvalidKeySpecException e) {
                            log.debug("Strange CVCA certificate that we can't get the key from, continuing anyway...", e);
                        } catch (NoSuchFieldException e) {
                            log.debug("Strange DV certificate with no AutheorizationRole, continuing anyway...", e);
                        }
                    } else {
                        log.debug("Key is not ECDSA, don't try to enrich with EC parameters.");
                    }
                } else {
                    log.debug("Cert is not CVC, no need to enrich with EC parameters.");
                }

                if (futureRollover) {
                    testNextKey(authenticationToken, ca, cacert, chain, caCertPublicKey, nextKeyAlias);
                    final CAToken catoken = ca.getCAToken();
                    if (nextKeyAlias != null) {
                        catoken.setNextCertSignKey(nextKeyAlias);
                    }
                    ca.setCAToken(catoken);
                    ca.setRolloverCertificateChain(chain);
                    // Save CA
                    caSession.editCA(authenticationToken, ca, true);
                    // Store certificate, but don't publish it yet (usedpublishers=null)
                    publishCACertificate(authenticationToken, chain, null, ca.getSubjectDN(), true);
                } else {
                    // Test and activate new key, publish certificate and generate CRL.
                    activateNextKeyAndCert(authenticationToken, caid, nextKeyAlias, ca, cacert, chain, caCertPublicKey);
                }

                // All OK
                String detailsMsg = intres.getLocalizedMessage("caadmin.certrespreceived", Integer.valueOf(caid));
                auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, detailsMsg);
            }
        } catch (CryptoTokenOfflineException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CADoesntExistsException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CertificateEncodingException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (CertificateException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        } catch (NoSuchProviderException e) {
            String msg = intres.getLocalizedMessage("caadmin.errorcertresp", Integer.valueOf(caid));
            log.info(msg);
            throw new EjbcaException(e.getMessage());
        }
        if (log.isTraceEnabled()) {
            log.trace("<receiveResponse: " + caid);
        }
    }

    /**
     * Verifies that the next signing key of the given CA is working. This is checked with {@link KeyTools#testKey}.
     *
     * @param authenticationToken Admin performing the test.
     * @param ca CA to test the key of.
     * @param cacert CA certificate from the request.
     * @param chain Certificate chain including the newly issued certificate.
     * @param caCertPublicKey Public key of CA. Must be fully usable, i.e. CVC DVCA keys must be have the full parameters from the CVCA.
     * @param nextKeyAlias Key alias to test, or null to test the current key alias given by the CA Token (or the next signing key as a fallback).
     * @throws CryptoTokenOfflineException
     * @throws IllegalKeyException
     */
    private void testNextKey(AuthenticationToken authenticationToken, final CA ca, final Certificate cacert, final List<Certificate> chain,
            PublicKey caCertPublicKey, String nextKeyAlias) throws CryptoTokenOfflineException, IllegalKeyException {
        final CAToken catoken = ca.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
        if (nextKeyAlias != null) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("SubjectKeyId for CA cert public key: "
                            + new String(Hex.encode(KeyTools.createSubjectKeyId(caCertPublicKey).getKeyIdentifier())));
                    log.debug("SubjectKeyId for CA next public key: "
                            + new String(Hex.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(nextKeyAlias)).getKeyIdentifier())));
                }
                KeyTools.testKey(cryptoToken.getPrivateKey(nextKeyAlias), caCertPublicKey, cryptoToken.getSignProviderName());
            } catch (InvalidKeyException e) { // java exception
                throw new IllegalKeyException(e); // cesecore exception
            }
        } else {
            // Since we don't specified the nextSignKey, we will just try the current or next CA sign key
            try {
                KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), caCertPublicKey,
                        cryptoToken.getSignProviderName());
            } catch (Exception e1) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN, trying CAKEYPURPOSE_CERTSIGN_NEXT...");
                    if (e1 instanceof InvalidKeyException) {
                        log.trace(e1);
                    } else {
                        // If it's not invalid key, we want to see more of the error
                        log.debug("Error: ", e1);
                    }
                }
                try {
                    KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)),
                            caCertPublicKey, cryptoToken.getSignProviderName());
                } catch (Exception e2) {
                    if (log.isDebugEnabled()) {
                        log.debug(
                                "The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN_NEXT either, giving up.");
                        if ((e2 instanceof InvalidKeyException) || (e2 instanceof IllegalArgumentException)) {
                            log.trace(e2);
                        } else {
                            // If it's not invalid key or missing authentication code, we want to see more of the error
                            log.debug("Error: ", e2);
                        }
                    }
                    throw new IllegalKeyException(e2);
                }
            }
        }
    }

    private void activateNextKeyAndCert(AuthenticationToken authenticationToken, int caid, String nextKeyAlias, final CA ca, final Certificate cacert,
            final List<Certificate> chain, PublicKey caCertPublicKey) throws CryptoTokenOfflineException, EjbcaException, InvalidAlgorithmException,
            CADoesntExistsException, AuthorizationDeniedException, CAOfflineException {
        final CAToken catoken = ca.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
        boolean activatedNextSignKey = false;
        if (nextKeyAlias != null) {
            try {
                if (log.isDebugEnabled()) {
                    log.debug("SubjectKeyId for CA cert public key: "
                            + new String(Hex.encode(KeyTools.createSubjectKeyId(caCertPublicKey).getKeyIdentifier())));
                    log.debug("SubjectKeyId for CA next public key: "
                            + new String(Hex.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(nextKeyAlias)).getKeyIdentifier())));
                }
                KeyTools.testKey(cryptoToken.getPrivateKey(nextKeyAlias), caCertPublicKey, cryptoToken.getSignProviderName());
            } catch (InvalidKeyException e) {
                throw new EjbcaException(ErrorCode.INVALID_KEY, e);
            }
            catoken.setNextCertSignKey(nextKeyAlias);
            catoken.activateNextSignKey();
            activatedNextSignKey = true;
        } else {
            // Since we don't specified the nextSignKey, we will just try the current or next CA sign key
            try {
                KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), caCertPublicKey,
                        cryptoToken.getSignProviderName());
            } catch (Exception e1) {
                log.debug(
                        "The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN, trying CAKEYPURPOSE_CERTSIGN_NEXT...");
                if (e1 instanceof InvalidKeyException) {
                    log.trace(e1);
                } else {
                    // If it's not invalid key, we want to see more of the error
                    log.debug("Error: ", e1);
                }
                try {
                    KeyTools.testKey(cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT)),
                            caCertPublicKey, cryptoToken.getSignProviderName());
                    // This was OK, so we must also activate the next signing key when importing this certificate
                    catoken.activateNextSignKey();
                    activatedNextSignKey = true;
                } catch (Exception e2) {
                    log.debug(
                            "The received certificate response does not match the CAs private signing key for purpose CAKEYPURPOSE_CERTSIGN_NEXT either, giving up.");
                    if ((e2 instanceof InvalidKeyException) || (e2 instanceof IllegalArgumentException)) {
                        log.trace(e2);
                    } else {
                        // If it's not invalid key or missing authentication code, we want to see more of the error
                        log.debug("Error: ", e2);
                    }
                    throw new EjbcaException(ErrorCode.INVALID_KEY, e2);
                }
            }
        }
        if (activatedNextSignKey) {
            // Activated the next signing key(s) so generate audit log
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("catoken.activatednextkey", caid));
            details.put("certSignKey", catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            details.put("crlSignKey", catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            details.put("sequence", catoken.getKeySequence());
            auditSession.log(EventTypes.CA_KEYACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, details);
        }
        ca.setCAToken(catoken);
        ca.setCertificateChain(chain);

        // Set status to active, so we can sign certificates for the external services below.
        ca.setStatus(CAConstants.CA_ACTIVE);

        final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);

        // activate External CA Services
        for (int type : ca.getExternalCAServiceTypes()) {
            try {
                ca.initExtendedService(cryptoToken, type, ca, cceConfig);
                final ExtendedCAServiceInfo info = ca.getExtendedCAServiceInfo(type);
                if (info instanceof BaseSigningCAServiceInfo) {
                    // Publish the extended service certificate, but only for active services
                    if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
                        final List<Certificate> extcacertificate = new ArrayList<Certificate>();
                        extcacertificate.add(((BaseSigningCAServiceInfo) info).getCertificatePath().get(0));
                        publishCACertificate(authenticationToken, extcacertificate, ca.getCRLPublishers(), ca.getSubjectDN());
                    }
                }
            } catch (Exception fe) {
                final String detailsMsg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", Integer.valueOf(caid));
                auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        String.valueOf(caid), null, null, detailsMsg);
                throw new EJBException(fe);
            }
        }
        // Set expire time
        ca.setExpireTime(CertTools.getNotAfter(cacert));
        // Save CA
        caSession.editCA(authenticationToken, ca, true);
        // Publish CA Certificate
        publishCACertificate(authenticationToken, chain, ca.getCRLPublishers(), ca.getSubjectDN());
        // Create initial CRL
        publishingCrlSession.forceCRL(authenticationToken, caid);
        publishingCrlSession.forceDeltaCRL(authenticationToken, caid);
    }

    @Override
    public ResponseMessage processRequest(AuthenticationToken admin, CAInfo cainfo, RequestMessage requestmessage)
            throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        final CA ca;
        List<Certificate> certchain = null;
        CertificateResponseMessage returnval = null;
        int caid = cainfo.getCAId();
        // check authorization
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocertresp", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Check that CA doesn't already exists
        CAData oldcadata = null;
        if (caid >= 0 && caid <= CAInfo.SPECIALCAIDBORDER) {
            String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());
            log.info(msg);
            throw new CAExistsException(msg);
        }
        oldcadata = caSession.findById(Integer.valueOf(caid));
        // If it did not exist with a certain DN (caid) perhaps a CA with the
        // same CA name exists?
        if (oldcadata == null) {
            oldcadata = caSession.findByName(cainfo.getName());
        }
        boolean processinternalca = false;
        if (oldcadata != null) {
            // If we find an already existing CA, there is a good chance that we
            // should throw an exception
            // Saying that the CA already exists.
            // However, if we have the same DN, and give the same name, we
            // simply assume that the admin actually wants
            // to treat an internal CA as an external CA, perhaps there is
            // different HSMs connected for root CA and sub CA?
            if (log.isDebugEnabled()) {
                log.debug("Old castatus=" + oldcadata.getStatus() + ", oldcaid=" + oldcadata.getCaId().intValue() + ", caid=" + cainfo.getCAId()
                        + ", oldcaname=" + oldcadata.getName() + ", name=" + cainfo.getName());
            }
            if (((oldcadata.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) || (oldcadata.getStatus() == CAConstants.CA_ACTIVE)
                    || (oldcadata.getStatus() == CAConstants.CA_EXTERNAL)) && (oldcadata.getCaId().intValue() == cainfo.getCAId())
                    && (oldcadata.getName().equals(cainfo.getName()))) {
                // Yes, we have all the same DN, CAName and the old CA is either
                // waiting for a certificate response or is active
                // (new CA or active CA that we want to renew)
                // or it is an external CA that we want to issue a new
                // certificate to
                processinternalca = true;
                if (oldcadata.getStatus() == CAConstants.CA_EXTERNAL) {
                    log.debug("Renewing an external CA.");
                } else {
                    log.debug("Processing an internal CA, as an external.");
                }
            } else {
                String msg = intres.getLocalizedMessage("caadmin.errorcaexists", cainfo.getName());
                log.info(msg);
                throw new CAExistsException(msg);
            }
        }

        // get signing CA
        if (cainfo.getSignedBy() > CAInfo.SPECIALCAIDBORDER || cainfo.getSignedBy() < 0) {
            try {
                final CA signca = caSession.getCAForEdit(admin, Integer.valueOf(cainfo.getSignedBy()));
                try {
                    // Check that the signer is valid
                    assertSignerValidity(admin, signca);

                    // Get public key from request
                    PublicKey publickey = requestmessage.getRequestPublicKey();

                    // Create cacertificate
                    Certificate cacertificate = null;
                    EndEntityInformation cadata = makeEndEntityInformation(cainfo);
                    // We can pass the PKCS10 request message as extra
                    // parameters
                    if (requestmessage instanceof PKCS10RequestMessage) {
                        ExtendedInformation extInfo = new ExtendedInformation();
                        PKCS10CertificationRequest pkcs10 = ((PKCS10RequestMessage) requestmessage).getCertificationRequest();
                        extInfo.setCustomData(ExtendedInformationFields.CUSTOM_PKCS10, new String(Base64.encode(pkcs10.getEncoded())));
                        cadata.setExtendedInformation(extInfo);
                    }
                    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
                    String sequence = null;
                    byte[] ki = requestmessage.getRequestKeyInfo();
                    if ((ki != null) && (ki.length > 0)) {
                        sequence = new String(ki);
                    }
                    final CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());
                    final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                            .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
                    cacertificate = signca.generateCertificate(signCryptoToken, cadata, publickey, -1, null, cainfo.getEncodedValidity(), certprofile,
                            sequence, cceConfig);
                    // X509ResponseMessage works for both X509 CAs and CVC CAs, should really be called CertificateResponsMessage
                    returnval = new X509ResponseMessage();
                    returnval.setCertificate(cacertificate);

                    // Build Certificate Chain
                    List<Certificate> rootcachain = signca.getCertificateChain();
                    certchain = new ArrayList<Certificate>();
                    certchain.add(cacertificate);
                    certchain.addAll(rootcachain);

                    if (!processinternalca) {
                        // If this is an internal CA, we don't create it and set
                        // a NULL token, since the CA is already created
                        if (cainfo instanceof X509CAInfo) {
                            log.info("Creating a X509 CA (process request)");
                            ca = new X509CA((X509CAInfo) cainfo);
                        } else if (cainfo instanceof CVCCAInfo) {
                            // CVC CA is a special type of CA for EAC electronic
                            // passports
                            log.info("Creating a CVC CA (process request)");
                            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
                            // Create CVCCA
                            ca = CvcCA.getInstance(cvccainfo);
                        } else {
                            ca = null;
                        }
                        ca.setCertificateChain(certchain);
                        CAToken token = new CAToken(ca.getCAId(), new NullCryptoToken().getProperties());
                        ca.setCAToken(token);

                        // set status to active
                        entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), CAConstants.CA_EXTERNAL, ca));
                        // cadatahome.create(cainfo.getSubjectDN(), cainfo.getName(), SecConst.CA_EXTERNAL, ca);
                    } else {
                        if (oldcadata.getStatus() == CAConstants.CA_EXTERNAL) {
                            // If it is an external CA we will not import the
                            // certificate later on here, so we want to
                            // update the CA in this instance with the new
                            // certificate so it is visible
                            ca = caSession.getCAForEdit(admin, oldcadata.getCaId());//getCAFromDatabase(oldcadata.getCaId());
                            ca.setCertificateChain(certchain);
                            if (log.isDebugEnabled()) {
                                log.debug("Storing new certificate chain for external CA " + cainfo.getName() + ", CA token type: "
                                        + ca.getCAToken().getClass().getName());
                            }
                            caSession.editCA(admin, ca, true);
                        } else {
                            // If it is an internal CA so we are "simulating"
                            // signing a real external CA we don't do anything
                            // because that CA is waiting to import a
                            // certificate
                            if (log.isDebugEnabled()) {
                                log.debug(
                                        "Not storing new certificate chain or updating CA for internal CA, simulating external: " + cainfo.getName());
                            }
                            ca = null;
                        }
                    }
                    // Publish CA certificates.
                    publishCACertificate(admin, certchain, signca.getCRLPublishers(), ca != null ? ca.getSubjectDN() : null);
                    // External CAs will not have any CRLs in this system, so we don't have to try to publish any CRLs
                } catch (CryptoTokenOfflineException e) {
                    String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                    log.error(msg, e);
                    throw e;
                }
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
                log.error(msg, e);
                throw new EJBException(e);
            }

        }

        if (certchain != null) {
            String msg = intres.getLocalizedMessage("caadmin.processedca", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, details);
        } else {
            String msg = intres.getLocalizedMessage("caadmin.errorprocess", cainfo.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.CA_EDITING, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid),
                    null, null, details);
        }
        return returnval;
    }

    @Override
    public void importCACertificate(AuthenticationToken admin, String caname, Collection<CertificateWrapper> wrappedCerts)
            throws AuthorizationDeniedException, CAExistsException, IllegalCryptoTokenException, CertificateImportException {
        List<Certificate> certificates = EJBTools.unwrapCertCollection(wrappedCerts);
        // Re-order if needed and validate chain
        if (certificates.size() != 1) {
            // In the case there is a chain, we require a full chain leading up to a root
            try {
                certificates = CertTools.createCertChain(certificates);
            } catch (CertPathValidatorException e) {
                throw new CertificateImportException("The provided certificates does not form a full certificate chain.");
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateImportException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new CertificateImportException(e);
            } catch (NoSuchProviderException e) {
                throw new CertificateImportException(e);
            } catch (CertificateException e) {
                throw new CertificateImportException(e);
            }
        }
        final Certificate caCertificate = certificates.iterator().next();
        if (!CertTools.isCA(caCertificate)) {
            throw new CertificateImportException("Only CA certificates can be imported using this function.");
        }
        CA ca = null;
        CAInfo cainfo = null;

        // Parameters common for both X509 and CVC CAs
        int certprofileid = CertTools.isSelfSigned(caCertificate) ? CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA
                : CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
        String subjectdn = CertTools.getSubjectDN(caCertificate);
        String validityString = "0d";
        int signedby = CertTools.isSelfSigned(caCertificate) ? CAInfo.SELFSIGNED : CAInfo.SIGNEDBYEXTERNALCA;
        log.info("Preparing to import of CA with Subject DN " + subjectdn);
        if (caCertificate instanceof X509Certificate) {
            X509Certificate x509CaCertificate = (X509Certificate) caCertificate;
            String subjectaltname = CertTools.getSubjectAlternativeName(x509CaCertificate);

            // Process certificate policies.
            ArrayList<CertificatePolicy> policies = new ArrayList<CertificatePolicy>();
            CertificateProfile certprof = certificateProfileSession.getCertificateProfile(certprofileid);
            if (certprof.getCertificatePolicies() != null && certprof.getCertificatePolicies().size() > 0) {
                policies.addAll(certprof.getCertificatePolicies());
            }
            final X509CAInfo x509cainfo = new X509CAInfo(subjectdn, caname, CAConstants.CA_EXTERNAL, certprofileid, validityString, signedby, null,
                    null);
            x509cainfo.setSubjectAltName(subjectaltname);
            x509cainfo.setPolicies(policies);
            x509cainfo.setExpireTime(CertTools.getNotAfter(x509CaCertificate));
            cainfo = x509cainfo;
        } else if (StringUtils.equals(caCertificate.getType(), "CVC")) {
            cainfo = new CVCCAInfo(subjectdn, caname, CAConstants.CA_EXTERNAL, certprofileid, validityString, signedby, null, null);
        } else {
            throw new CertificateImportException("Certificate was of an unknown type: " + caCertificate.getType());
        }

        cainfo.setDescription("CA created by certificate import.");

        if (cainfo instanceof X509CAInfo) {
            log.info("Creating a X509 CA (process request)");
            ca = new X509CA((X509CAInfo) cainfo);
        } else if (cainfo instanceof CVCCAInfo) {
            // CVC CA is a special type of CA for EAC electronic passports
            log.info("Creating a CVC CA (process request)");
            CVCCAInfo cvccainfo = (CVCCAInfo) cainfo;
            ca = CvcCA.getInstance(cvccainfo);
        } else {
            throw new IllegalStateException("CAInfo object was of an unknown type: " + cainfo.getCAType());
        }
        ca.setCertificateChain(certificates);
        CAToken token = new CAToken(ca.getCAId(), new NullCryptoToken().getProperties());
        try {
            ca.setCAToken(token);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalCryptoTokenException(e);
        }
        // Add CA
        caSession.addCA(admin, ca);
        // Persist ("Publish") the CA certificates to the local CertificateData database.
        publishCACertificate(admin, certificates, null, ca.getSubjectDN());
    }

    @Override
    public void updateCACertificate(final AuthenticationToken authenticationToken, final int caId, Collection<CertificateWrapper> wrappedCerts)
            throws CADoesntExistsException, AuthorizationDeniedException, CertificateImportException {
        List<Certificate> certificates = EJBTools.unwrapCertCollection(wrappedCerts);
        // Re-order if needed and validate chain
        if (certificates.size() != 1) {
            // In the case there is a chain, we require a full chain leading up to a root
            try {
                certificates = CertTools.createCertChain(certificates);
            } catch (CertPathValidatorException e) {
                throw new CertificateImportException("The provided certificates does not form a full certificate chain.");
            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateImportException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new CertificateImportException(e);
            } catch (NoSuchProviderException e) {
                throw new CertificateImportException(e);
            } catch (CertificateException e) {
                throw new CertificateImportException(e);
            }
        }
        final Certificate newCaCertificate = certificates.iterator().next();
        if (!CertTools.isCA(newCaCertificate)) {
            throw new CertificateImportException("Only CA certificates can be imported using this function.");
        }
        final String newSubjectDn = CertTools.getSubjectDN(newCaCertificate);
        log.info("Preparing to import of update for CA with Subject DN " + newSubjectDn);
        final CA ca = caSession.getCAForEdit(authenticationToken, caId);
        final CAInfo caInfo = ca.getCAInfo();
        final Certificate oldCaCertificate = ca.getCACertificate();
        if (ca.getStatus() != CAConstants.CA_EXTERNAL) {
            throw new CertificateImportException("Only able to update imported CA certificate of external CAs.");
        }
        if (CertTools.getFingerprintAsString(oldCaCertificate).equals(CertTools.getFingerprintAsString(newCaCertificate))) {
            // The admin might want to update the chain even if the leaf CA cert is the same
            boolean sameAsExisting = true;
            if (caInfo.getCertificateChain().size() == certificates.size()) {
                for (int i = 1; i < certificates.size(); i++) {
                    if (!CertTools.getFingerprintAsString(oldCaCertificate).equals(CertTools.getFingerprintAsString(newCaCertificate))) {
                        sameAsExisting = false;
                    }
                }
            } else {
                sameAsExisting = false;
            }
            if (sameAsExisting) {
                throw new CertificateImportException("The CA certificate chain is already imported.");
            }
        }

        final String oldSubjectDn = CertTools.getSubjectDN(oldCaCertificate);
        boolean storeCscaWithChangedSubjectDn = false;
        if (!oldSubjectDn.equals(newSubjectDn)) {
            // Could be a CSCA certificate with other SubjectDN SN (C and CN attribute must match).
            // This is only for X.509 CAs (serialNumber in CVC certificates is the key sequence).
            // For example the German CSCA has same subjectDN except a SN (serialNumber) element after rollover.
            boolean sameCsca = true;
            final Map<String, String> oldSubjectDnMap = DNFieldsUtil.dnStringToMap(oldSubjectDn);
            final Map<String, String> newSubjectDnMap = DNFieldsUtil.dnStringToMap(newSubjectDn);
            if (!DNFieldsUtil.mapContainsCountryAndCN(oldSubjectDnMap)) {
                sameCsca = false;
            }
            if (!DNFieldsUtil.mapContainsCountryAndCN(newSubjectDnMap)) {
                sameCsca = false;
            }
            if (!DNFieldsUtil.dnEqualsWithOtherSerialNumber(oldSubjectDnMap, newSubjectDnMap)) {
                sameCsca = false;
            }
            if (!sameCsca) {
                throw new CertificateImportException(
                        "Only able to update imported CA certificate if Subject DN of the leaf CA certificate is the same.");
            }
            if (caInfo instanceof X509CAInfo) {
                caInfo.setSubjectDN(newSubjectDn);
                caInfo.setCertificateChain(certificates); // required for storing!
                storeCscaWithChangedSubjectDn = true;
            }
        }

        // Check that update is newer if information is present
        final Date newValidFrom = CertTools.getNotBefore(newCaCertificate);
        final Date oldValidFrom = CertTools.getNotBefore(oldCaCertificate);
        if (log.isDebugEnabled()) {
            log.debug("Current valid from: " + ValidityDate.formatAsISO8601(oldValidFrom, TimeZone.getDefault()) + " Import valid from: "
                    + ValidityDate.formatAsISO8601(newValidFrom, TimeZone.getDefault()));
        }
        if (newValidFrom != null && oldValidFrom != null && newValidFrom.before(oldValidFrom)) {
            throw new CertificateImportException(
                    "Only able to update imported CA certificate if new certificate is issued after the currently used.");
        }
        ca.setExpireTime(CertTools.getNotAfter(newCaCertificate));
        // Could be signed by an external CA now or vice versa
        if (CertTools.isSelfSigned(newCaCertificate)) {
            caInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
            caInfo.setSignedBy(CAInfo.SELFSIGNED);
        } else {
            caInfo.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
            caInfo.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
        }
        ca.setCertificateChain(certificates);

        // Only for CSCAs: Set state to CAConstants.CA_UNINITIALIZED to store the CA with a new subject-DN and CA-ID.
        if (storeCscaWithChangedSubjectDn) {
            final int currentCaState = caInfo.getStatus();
            caInfo.setCertificateChain(certificates);
            // Don't set CA-ID here, it is derived later by the CA certificates subject DN in editCA(), if we set state to UNINITIALIZED.
            // caInfo.setCAId(CAData.calculateCAId(ca.getSubjectDN()));
            caInfo.setStatus(CAConstants.CA_UNINITIALIZED);
            editCA(authenticationToken, caInfo);
            caInfo.setStatus(currentCaState);
            // Add CA certificate chain again, because it is removed in createCA() for CAs with state CAConstants.CA_UNINITIALIZED.
            caInfo.setCertificateChain(certificates);
        }

        // Update CA in database
        editCA(authenticationToken, caInfo);
        // Update the CA certificate in the local database
        publishCACertificate(authenticationToken, certificates, null, ca.getSubjectDN());
    }

    @Override
    public void initExternalCAService(AuthenticationToken admin, int caid, ExtendedCAServiceInfo info)
            throws CADoesntExistsException, AuthorizationDeniedException, CAOfflineException {
        // check authorization
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), caSession.getCAInfoInternal(caid));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        if (ca.getStatus() == CAConstants.CA_OFFLINE) {
            String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getName());
            throw new CAOfflineException(msg);
        }
        ArrayList<ExtendedCAServiceInfo> infos = new ArrayList<ExtendedCAServiceInfo>();
        infos.add(info);
        activateAndPublishExternalCAServices(admin, infos, ca);
        // Update CA in database
        caSession.editCA(admin, ca, true);
    }

    @Override
    public void renewCA(AuthenticationToken authenticationToken, int caid, boolean regenerateKeys, Date customNotBefore,
            final boolean createLinkCertificate) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        try {
            renewCAInternal(authenticationToken, caid, regenerateKeys, customNotBefore, createLinkCertificate, /*newSubjectDN=*/null);
        } catch (CANameChangeRenewalException e) {
            throw new IllegalStateException(e);
        }
    }

    private void renewCAInternal(AuthenticationToken authenticationToken, int caid, boolean regenerateKeys, Date customNotBefore,
            final boolean createLinkCertificate, String newSubjectDn)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException {
        final CA ca = caSession.getCAForEdit(authenticationToken, caid);
        final CAToken caToken = ca.getCAToken();
        final Properties oldProperties = caToken.getProperties();
        final String oldSequence = caToken.getKeySequence();
        final String currentSignKeyAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        String nextSignKeyAlias = currentSignKeyAlias;
        final int cryptoTokenId = caToken.getCryptoTokenId();
        if (regenerateKeys) {
            nextSignKeyAlias = caToken.generateNextSignKeyAlias();
            if (cryptoTokenManagementSession.getKeyPairInfo(authenticationToken, cryptoTokenId, nextSignKeyAlias) == null) {
                // Ok.. No such key..
                try {
                    cryptoTokenManagementSession.createKeyPairWithSameKeySpec(authenticationToken, cryptoTokenId, currentSignKeyAlias,
                            nextSignKeyAlias);
                    // Audit log CA key generation
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", intres.getLocalizedMessage("catoken.generatedkeys", caid, true, false));
                    details.put("oldproperties", oldProperties);
                    details.put("oldsequence", oldSequence);
                    details.put("properties", caToken.getProperties());
                    details.put("sequence", caToken.getKeySequence());
                    auditSession.log(EventTypes.CA_KEYGEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                            String.valueOf(caid), null, null, details);
                    ca.setCAToken(caToken);
                    caSession.editCA(authenticationToken, ca, true);
                } catch (AuthorizationDeniedException | CryptoTokenOfflineException e2) {
                    throw e2;
                } catch (Exception e2) {
                    throw new RuntimeException(e2);
                }
            } else {
                log.warn("Key generation request for existing key alias ignored for CA=" + ca.getCAId() + ", CryptoToken=" + cryptoTokenId
                        + " and alias=" + nextSignKeyAlias);
            }
        }
        renewCAInternal(authenticationToken, caid, nextSignKeyAlias, customNotBefore, createLinkCertificate, newSubjectDn);
    }

    @Override
    public void renewCA(final AuthenticationToken authenticationToken, final int caid, final String nextSignKeyAlias, Date customNotBefore,
            final boolean createLinkCertificate) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        try {
            renewCAInternal(authenticationToken, caid, nextSignKeyAlias, customNotBefore, createLinkCertificate, /*newSubjectDN=*/null);
        } catch (CANameChangeRenewalException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void renewCANewSubjectDn(AuthenticationToken admin, int caid, boolean regenerateKeys, Date customNotBefore,
            final boolean createLinkCertificate, String newSubjectDn)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException {
        renewCAInternal(admin, caid, regenerateKeys, customNotBefore, createLinkCertificate, newSubjectDn);
    }

    @Override
    public void renewCANewSubjectDn(AuthenticationToken admin, int caid, final String nextSignKeyAlias, Date customNotBefore,
            final boolean createLinkCertificate, String newSubjectDn)
            throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException {
        renewCAInternal(admin, caid, nextSignKeyAlias, customNotBefore, createLinkCertificate, newSubjectDn);
    }

    private void renewCAInternal(final AuthenticationToken authenticationToken, int caid, final String nextSignKeyAlias, Date customNotBefore,
            final boolean createLinkCertificate, String newSubjectDN)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, CANameChangeRenewalException {
        if (log.isTraceEnabled()) {
            log.trace(">CAAdminSession, renewCA(), caid=" + caid);
        }
        List<Certificate> cachain = null;
        Certificate cacertificate = null;
        // check authorization
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CARENEW.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorenew", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA info.
        try {
            CA ca = caSession.getCAForEdit(authenticationToken, caid);

            String newCAName = null;
            boolean subjectDNWillBeChanged = newSubjectDN != null && !newSubjectDN.isEmpty();
            if (subjectDNWillBeChanged) {
                GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession
                        .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                if (!globalConfig.getEnableIcaoCANameChange()) {
                    final String errorMessage = "The \"Enable ICAO CA Name Change\" feature is disabled by administrator. Aborting CA Name Change renewal!";
                    log.error(errorMessage);
                    throw new IllegalStateException(errorMessage);
                }
                if (ca.getCAType() != CAInfo.CATYPE_X509) {
                    final String errorMessage = "CVC CA Name Change operation is not supported (Only for X509 CA)";
                    log.error(errorMessage);
                    throw new IllegalStateException(errorMessage);
                }
                if (CertTools.stringToBCDNString(newSubjectDN).equalsIgnoreCase(ca.getSubjectDN())) {
                    final String errorMessage = "New Subject DN " + newSubjectDN
                            + " is the same as current. Please choose another name. Aborting CA Name Change renewal.";
                    log.error(errorMessage);
                    throw new CANameChangeRenewalException(errorMessage);
                }
                newCAName = CertTools.getPartFromDN(newSubjectDN, "CN");
                if (newCAName == null) {
                    final String errorMessage = "New Subject DN " + newSubjectDN
                            + " does not have Common Name or it is invalid. Aborting CA Name Change renewal!";
                    log.error(errorMessage);
                    throw new CANameChangeRenewalException(errorMessage);
                }
                if (caSession.existsCa(newCAName)) {
                    final String errorMessage = "There already exists CA with the name = " + newCAName
                            + ". Please delete it or specify another Subject DN. Aborting CA Name Change renewal.";
                    log.error(errorMessage);
                    throw new CANameChangeRenewalException(errorMessage);
                }
                if (crlStoreSession.getLastCRL(newSubjectDN, false) != null) {
                    final String errorMessage = "There are already stored some CRL data with issuer DN equal to specified new SubjectDN = "
                            + newSubjectDN + ". Please delete them. Aborting CA Name Change renewal.";
                    log.error(errorMessage);
                    throw new IllegalStateException(errorMessage);
                }
                if (ca.getSignedBy() != CAInfo.SELFSIGNED) {
                    final String errorMessage = "CA name change operation is not supported for self-signed CA";
                    log.error(errorMessage);
                    throw new IllegalStateException(errorMessage);
                }
                log.info("CA Name Change (Subject DN change) has been triggered from: " + ca.getSubjectDN() + " to " + newSubjectDN);
            }

            if (ca.getStatus() == CAConstants.CA_OFFLINE || ca.getCAToken().getTokenStatus(true,
                    cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId())) == CryptoToken.STATUS_OFFLINE) {
                String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getName());
                throw new CryptoTokenOfflineException(msg);
            }
            if (ca.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                // We should never get here
                log.error("Directly renewing a CA signed by external can not be done");
                throw new NotSupportedException("Directly renewing a CA signed by external can not be done");
            }

            final CAToken caToken = ca.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
            cryptoToken.testKeyPair(nextSignKeyAlias);
            caToken.setNextCertSignKey(nextSignKeyAlias);
            // Activate the next signing key(s) and generate audit log
            caToken.activateNextSignKey();
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", intres.getLocalizedMessage("catoken.activatednextkey", caid));
            details.put("certSignKey", caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            details.put("crlSignKey", caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            details.put("sequence", caToken.getKeySequence());
            auditSession.log(EventTypes.CA_KEYACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, details);
            // if issuer is in-system CA or selfsigned, then generate new certificate.
            log.info("Renewing CA using " + caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            final PublicKey caPublicKey = cryptoToken.getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            ca.setCAToken(caToken);
            final CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(ca.getCertificateProfileId());
            mergeCertificatePoliciesFromCAAndProfile(ca.getCAInfo(), certprofile);

            final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                    .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);

            //Save old CA certificate before renewal, so we can use its expire date when creating link certificate
            Certificate oldCaCertificate = ca.getCACertificate();

            if (ca.getSignedBy() == CAInfo.SELFSIGNED) {
                if (subjectDNWillBeChanged) {
                    ca.setSubjectDN(newSubjectDN);
                    ca.setName(newCAName); // use CN value for new CA name
                    ca.setCAId(0); //set it to 0, because we want to new id to be generated based on newSubjectDn
                    ((X509CA) ca).setNameChanged(true);
                }
                // create selfsigned certificate
                EndEntityInformation cainfodata = makeEndEntityInformation(ca.getCAInfo());
                // get from CAtoken to make sure it is fresh
                String sequence = caToken.getKeySequence();

                cacertificate = ca.generateCertificate(cryptoToken, cainfodata, caPublicKey, -1, customNotBefore, ca.getEncodedValidity(),
                        certprofile, sequence, cceConfig);
                // Build Certificate Chain
                cachain = new ArrayList<Certificate>();
                cachain.add(cacertificate);

                // Save renewed certificate for later use (we'll need their Subject DN within CA renewal with name change)
                final List<Certificate> certificateChain = ca.getCertificateChain();
                final List<Certificate> renewedCertificateChain = ca.getRenewedCertificateChain() != null ? ca.getRenewedCertificateChain()
                        : new ArrayList<Certificate>();
                renewedCertificateChain.add(certificateChain != null ? certificateChain.get(certificateChain.size() - 1) : null);
                ca.setRenewedCertificateChain(renewedCertificateChain);
            } else {
                // Resign with CA above.
                if (ca.getSignedBy() > CAInfo.SPECIALCAIDBORDER || ca.getSignedBy() < 0) {
                    // Create CA signed by other internal CA.
                    final CA signca = caSession.getCAForEdit(authenticationToken, Integer.valueOf(ca.getSignedBy()));
                    // Check that the signer is valid
                    assertSignerValidity(authenticationToken, signca);
                    // Create cacertificate
                    EndEntityInformation cainfodata = makeEndEntityInformation(ca.getCAInfo());
                    String sequence = caToken.getKeySequence(); // get from CAtoken to make sure it is fresh
                    CryptoToken signCryptoToken = cryptoTokenSession.getCryptoToken(signca.getCAToken().getCryptoTokenId());

                    cacertificate = signca.generateCertificate(signCryptoToken, cainfodata, caPublicKey, -1, customNotBefore, ca.getEncodedValidity(),
                            certprofile, sequence, cceConfig);
                    // Build Certificate Chain
                    Collection<Certificate> rootcachain = signca.getCertificateChain();
                    cachain = new ArrayList<Certificate>();
                    cachain.add(cacertificate);
                    cachain.addAll(rootcachain);
                }
            }
            // Set statuses and expire time
            ca.setExpireTime(CertTools.getNotAfter(cacertificate));
            ca.setStatus(CAConstants.CA_ACTIVE);
            // Set the new certificate chain that we have created above
            ca.setCertificateChain(cachain);
            // We need to save all this, audit logging that the CA is changed
            int caidBeforeNameChange = -1;
            if (subjectDNWillBeChanged) {
                ((X509CA) ca).createOrRemoveLinkCertificateDuringCANameChange(cryptoToken, createLinkCertificate, certprofile, cceConfig, oldCaCertificate);
                caidBeforeNameChange = caid;
                caid = CAData.calculateCAId(newSubjectDN).intValue(); // recalculate the caid to corresponds to new CA
                ca.setCAId(caid); // it was set to 0 above
                caSession.addCA(authenticationToken, ca); //add new CA into database
            } else {
                ca.createOrRemoveLinkCertificate(cryptoToken, createLinkCertificate, certprofile, cceConfig, oldCaCertificate);
                caSession.editCA(authenticationToken, ca, true);
            }

            // Publish the new CA certificate
            publishCACertificate(authenticationToken, cachain, ca.getCRLPublishers(), ca.getSubjectDN());
            publishingCrlSession.forceCRL(authenticationToken, caid);
            publishingCrlSession.forceDeltaCRL(authenticationToken, caid);

            if (subjectDNWillBeChanged) {
                // If CA has gone through Name Change, add new caid to available CAs for every certificate profile
                //that had the caid before the Name Change)
                Map<Integer, String> allCertificateProfileIdMap = certificateProfileSession.getCertificateProfileIdToNameMap();
                for (Map.Entry<Integer, String> certificateProfileEntry : allCertificateProfileIdMap.entrySet()) {
                    CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileEntry.getKey());
                    List<Integer> availCAs = certificateProfile.getAvailableCAs();
                    if (availCAs.contains(caidBeforeNameChange) && !availCAs.contains(caid)) {
                        availCAs.add(caid);
                        certificateProfile.setAvailableCAs(availCAs);
                        certificateProfileSession.changeCertificateProfile(authenticationToken, certificateProfileEntry.getValue(),
                                certificateProfile);
                    }
                }

                //Like for certificate profiles we need to the same again for end entity profiles
                Map<Integer, String> allEndEntityProfileIdMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
                for (Integer endEntityProfileId : allEndEntityProfileIdMap.keySet()) {
                    EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(endEntityProfileId);
                    Collection<Integer> availCAs = endEntityProfile.getAvailableCAs();
                    if (availCAs.contains(caidBeforeNameChange) && !availCAs.contains(caid)) {
                        availCAs.add(caid);
                        endEntityProfile.setAvailableCAs(availCAs);
                        endEntityProfileSession.changeEndEntityProfile(authenticationToken, allEndEntityProfileIdMap.get(endEntityProfileId),
                                endEntityProfile);
                    }
                }
                // If CA has gone through Name Change, clone all this CA specific access rules with new one with replaced caid for every roles.
                roleSession.updateCaId(caidBeforeNameChange, caid, true, false);
            }
            // Audit log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.renewdca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CryptoTokenOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (CANameChangeRenewalException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrenewca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_RENEWED, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<CAAdminSession, renewCA(), caid=" + caid);
        }
    }

    @Override
    public void rolloverCA(final AuthenticationToken authenticationToken, final int caid)
            throws AuthorizationDeniedException, CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">CAAdminSession, rolloverCA(), caid=" + caid);
        }
        // check authorization. we require RENEWCA access for this
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CARENEW.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorollover", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA info.
        try {
            CA ca = caSession.getCAForEdit(authenticationToken, caid);
            final CAToken caToken = ca.getCAToken();
            final List<Certificate> rolloverChain = ca.getRolloverCertificateChain();
            if (rolloverChain == null) {
                // We should never get here
                log.error("Can't roll over a CA without a roll over certificate chain");
                throw new IllegalStateException("Can't roll over a CA without a roll over certificate chain");
            }

            // Replace certificate chain
            caToken.activateNextSignKey(); // also clears roll over status
            ca.setCAToken(caToken);
            ca.setCertificateChain(rolloverChain);
            ca.clearRolloverCertificateChain();
            ca.setExpireTime(CertTools.getNotAfter(rolloverChain.get(0)));
            // We need to save all this, audit logging that the CA is changed
            caSession.editCA(authenticationToken, ca, true);

            // Publish the new CA certificate. Prior to this point it should have been stored but not published.
            publishCACertificate(authenticationToken, rolloverChain, ca.getCRLPublishers(), ca.getSubjectDN());

            // Change the status of the CA certificate from CERT_ROLLOVERPENDING to CERT_ACTIVE
            certificateStoreSession.setRolloverDoneStatus(authenticationToken, CertTools.getFingerprintAsString(rolloverChain.get(0)));
            publishingCrlSession.forceCRL(authenticationToken, caid);
            publishingCrlSession.forceDeltaCRL(authenticationToken, caid);
            // Audit log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.rolledoverca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_ROLLEDOVER, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CryptoTokenOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrolloverca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_ROLLEDOVER, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw e;
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrolloverca", Integer.valueOf(caid));
            auditSession.log(EjbcaEventTypes.CA_ROLLEDOVER, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<CAAdminSession, rolloverCA(), caid=" + caid);
        }
    }

    @Override
    public byte[] getLatestLinkCertificate(final int caId) throws CADoesntExistsException {
        try {
            CA ca = caSession.getCANoLog(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Fetching link certificate user.")), caId);
            return ca.getLatestLinkCertificate();
        } catch (AuthorizationDeniedException e) {
            throw new RuntimeException(e); // Should always be allowed
        }
    }

    @Override
    public void revokeCA(AuthenticationToken admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
        // check authorization
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorevoke", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA info.
        CA ca = caSession.getCAForEdit(admin, caid);
        if(ca == null) {
            throw new CADoesntExistsException("No CA with id " + caid + " found");
        }
        try {
            // Revoke all issued CA certificates for this CA
            final List<CertificateDataWrapper> cacerts = certificateStoreSession.getCertificateDatasBySubject(ca.getSubjectDN());
            final Date now = new Date();
            for (final CertificateDataWrapper cdw : cacerts) {
                revocationSession.revokeCertificateInNewTransaction(admin, cdw, ca.getCRLPublishers(), now, reason, ca.getSubjectDN());
            }
            // Revoke all certificates issued by this CA. If this is a root CA the CA certificates will be included in this batch as well
            // but if this is a subCA these are only the "entity" certificates issued by this CA
            if (ca.getStatus() != CAConstants.CA_EXTERNAL) {
                certificateStoreSession.revokeAllCertByCA(admin, ca.getSubjectDN(), reason);
                publishingCrlSession.forceCRL(admin, ca.getCAId());
            }
            ca.setRevocationReason(reason);
            ca.setRevocationDate(new Date());
            if (ca.getStatus() != CAConstants.CA_EXTERNAL) {
                ca.setStatus(CAConstants.CA_REVOKED);
            }
            // Store new status, audit logging
            caSession.editCA(admin, ca, true);
            final String detailsMsg = intres.getLocalizedMessage("caadmin.revokedca", ca.getName(), Integer.valueOf(reason));
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } catch (CADoesntExistsException | CertificateRevokeException | CryptoTokenOfflineException | CAOfflineException e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrevoke", ca.getName());
            auditSession.log(EjbcaEventTypes.CA_REVOKED, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new EJBException(e);
        }
    }

    @Override
    public void importCAFromKeyStore(AuthenticationToken admin, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) {
        try {
            // check authorization
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtocreateca", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }
            // load keystore
            java.security.KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new java.io.ByteArrayInputStream(p12file), keystorepass.toCharArray());
            // Extract signature keys
            if (privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias)) {
                throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
                String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey(privateSignatureKeyAlias, privkeypass.toCharArray());
            log.debug("ImportSignatureKeyAlgorithm=" + p12PrivateSignatureKey.getAlgorithm());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if (!keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
                Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
                if (encryptionCertChain.length < 1) {
                    String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
                    log.error(msg);
                    throw new Exception(msg);
                }
                caEncryptionCertificate = encryptionCertChain[0];
                p12PrivateEncryptionKey = (PrivateKey) keystore.getKey(privateEncryptionKeyAlias, privkeypass.toCharArray());
                p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            }
            importCAFromKeys(admin, caname, keystorepass, signatureCertChain, p12PublicSignatureKey, p12PrivateSignatureKey, p12PrivateEncryptionKey,
                    p12PublicEncryptionKey);
        } catch (Exception e) {
            String detailsMsg = intres.getLocalizedMessage("caadmin.errorimportca", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null,
                    detailsMsg);
            throw new EJBException(e);
        }
    }

    @Override
    public void removeCAKeyStore(AuthenticationToken admin, String caname) throws EJBException {
        if (log.isTraceEnabled()) {
            log.trace(">removeCAKeyStore");
        }
        try {
            // check authorization
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremovecatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                        null, details);
            }
            CA ca = caSession.getCAForEdit(admin, caname);
            final CAToken currentCaToken = ca.getCAToken();
            final int cryptoTokenId = currentCaToken.getCryptoTokenId();
            CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
            if (!(cryptoToken instanceof SoftCryptoToken)) {
                throw new Exception("Cannot export anything but a soft token.");
            }
            cryptoTokenManagementSession.deactivate(admin, cryptoTokenId);
            // Create a new CAToken with the same properties but without the reference to the removed CryptoToken
            cryptoTokenSession.removeCryptoToken(cryptoTokenId);
            final CAToken newCaToken = new CAToken(0, currentCaToken.getProperties());
            newCaToken.setKeySequence(newCaToken.getKeySequence());
            newCaToken.setKeySequenceFormat(newCaToken.getKeySequenceFormat());
            newCaToken.setSignatureAlgorithm(newCaToken.getSignatureAlgorithm());
            newCaToken.setEncryptionAlgorithm(newCaToken.getEncryptionAlgorithm());
            ca.setCAToken(newCaToken);
            // Set this CA to offline, since it cannot be used without a CryptoToken this is probably intended.
            ca.setStatus(CAConstants.CA_OFFLINE);
            // Save to database
            caSession.editCA(admin, ca, false);
            // Log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.removedcakeystore", Integer.valueOf(ca.getCAId()));
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(ca.getCAId()), null, null, detailsMsg);
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorremovecakeystore", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_REMOVETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, detailsMsg);
            throw new EJBException(detailsMsg, e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeCAKeyStore");
        }
    }

    @Override
    public void restoreCAKeyStore(AuthenticationToken authenticationToken, String caname, byte[] p12file, String keystorepass, String privkeypass,
            String privateSignatureKeyAlias, String privateEncryptionKeyAlias) {
        if (log.isTraceEnabled()) {
            log.trace(">restoreCAKeyStore");
        }
        try {
            // check authorization
            if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
                final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtorestorecatoken", caname);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                        null, null, null, detailsMsg);
            }
            CA thisCa = caSession.getCAForEdit(authenticationToken, caname);
            final CAToken thisCAToken = thisCa.getCAToken();
            CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(thisCAToken.getCryptoTokenId());
            if (cryptoToken != null) {
                throw new Exception("CA already has an existing CryptoToken reference: " + cryptoToken.getId());
            }
            // load keystore from input
            KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(p12file), keystorepass.toCharArray());
            // Extract signature keys
            if (privateSignatureKeyAlias == null || !keystore.isKeyEntry(privateSignatureKeyAlias)) {
                throw new Exception("Alias \"" + privateSignatureKeyAlias + "\" not found.");
            }
            Certificate[] signatureCertChain = KeyTools.getCertChain(keystore, privateSignatureKeyAlias);
            if (signatureCertChain.length < 1) {
                String msg = "Cannot load certificate chain with alias " + privateSignatureKeyAlias;
                log.error(msg);
                throw new Exception(msg);
            }
            Certificate caSignatureCertificate = signatureCertChain[0];
            PublicKey p12PublicSignatureKey = caSignatureCertificate.getPublicKey();
            PrivateKey p12PrivateSignatureKey = null;
            p12PrivateSignatureKey = (PrivateKey) keystore.getKey(privateSignatureKeyAlias, privkeypass.toCharArray());

            // Extract encryption keys
            PrivateKey p12PrivateEncryptionKey = null;
            PublicKey p12PublicEncryptionKey = null;
            Certificate caEncryptionCertificate = null;
            if (privateEncryptionKeyAlias != null) {
                if (!keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Alias \"" + privateEncryptionKeyAlias + "\" not found.");
                }
                Certificate[] encryptionCertChain = KeyTools.getCertChain(keystore, privateEncryptionKeyAlias);
                if (encryptionCertChain.length < 1) {
                    String msg = "Cannot load certificate chain with alias " + privateEncryptionKeyAlias;
                    log.error(msg);
                    throw new Exception(msg);
                }
                caEncryptionCertificate = encryptionCertChain[0];
                p12PrivateEncryptionKey = (PrivateKey) keystore.getKey(privateEncryptionKeyAlias, privkeypass.toCharArray());
                p12PublicEncryptionKey = caEncryptionCertificate.getPublicKey();
            } else {
                throw new Exception("Missing encryption key");
            }

            // Sign something to see that we are restoring the right private signature key
            // BC should support the first algorithm so there is no need to use the SignWithWorkingAlgorithm class.
            final String testSigAlg = AlgorithmTools.getSignatureAlgorithms(thisCa.getCACertificate().getPublicKey()).get(0);
            // Sign with imported private key
            byte[] input = "Test data...".getBytes();
            Signature signature = Signature.getInstance(testSigAlg, BouncyCastleProvider.PROVIDER_NAME);
            signature.initSign(p12PrivateSignatureKey);
            signature.update(input);
            byte[] signed = signature.sign();
            // Verify with public key from CA certificate
            signature = Signature.getInstance(testSigAlg, BouncyCastleProvider.PROVIDER_NAME);
            signature.initVerify(thisCa.getCACertificate().getPublicKey());
            signature.update(input);
            if (!signature.verify(signed)) {
                throw new Exception("Could not use private key for verification. Wrong p12-file for this CA?");
            }
            // Import the keys and save to database
            CAToken catoken = importKeysToCAToken(authenticationToken, keystorepass, thisCAToken.getProperties(), p12PrivateSignatureKey,
                    p12PublicSignatureKey, p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain, thisCa.getCAId());
            thisCa.setCAToken(catoken);
            // Finally save the CA
            caSession.editCA(authenticationToken, thisCa, true);
            // Log
            final String detailsMsg = intres.getLocalizedMessage("caadmin.restoredcakeystore", Integer.valueOf(thisCa.getCAId()));
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    String.valueOf(thisCa.getCAId()), null, null, detailsMsg);
        } catch (Exception e) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errorrestorecakeystore", caname, "PKCS12", e.getMessage());
            auditSession.log(EjbcaEventTypes.CA_RESTORETOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                    null, null, null, detailsMsg);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<restoreCAKeyStore");
        }
    }

    @Override
    public void importCAFromKeys(AuthenticationToken authenticationToken, String caname, String keystorepass, Certificate[] signatureCertChain,
            PublicKey p12PublicSignatureKey, PrivateKey p12PrivateSignatureKey, PrivateKey p12PrivateEncryptionKey, PublicKey p12PublicEncryptionKey)
            throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, IllegalCryptoTokenException, AuthorizationDeniedException,
            CAExistsException, CAOfflineException {
        // Transform into token
        int caId = StringTools.strip(CertTools.getSubjectDN(signatureCertChain[0])).hashCode(); // caid
        CAToken catoken = null;
        try {
            catoken = importKeysToCAToken(authenticationToken, keystorepass, null, p12PrivateSignatureKey, p12PublicSignatureKey,
                    p12PrivateEncryptionKey, p12PublicEncryptionKey, signatureCertChain, caId);
        } catch (OperatorCreationException e) {
            log.error(e.getLocalizedMessage(), e);
            throw new EJBException(e);
        }
        log.debug("CA-Info: " + catoken.getSignatureAlgorithm() + " " + catoken.getEncryptionAlgorithm());
        // Identify the key algorithms for extended CA services, OCSP, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(p12PublicSignatureKey);
        String keySpecification = AlgorithmTools.getKeySpecification(p12PublicSignatureKey);
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        CA ca = importCA(authenticationToken, caname, keystorepass, signatureCertChain, catoken, keyAlgorithm, keySpecification);
        // Finally audit log
        String msg = intres.getLocalizedMessage("caadmin.importedca", caname, "PKCS12", ca.getStatus());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.CA_IMPORT, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, authenticationToken.toString(),
                String.valueOf(ca.getCAId()), null, null, details);
    }

    /**
     * Method that import CA token keys from a P12 file. Was originally used when upgrading from old EJBCA versions. Only supports SHA1 and SHA256
     * with RSA or ECDSA and SHA1 with DSA.
     * @throws OperatorCreationException
     * @throws AuthorizationDeniedException
     */
    private CAToken importKeysToCAToken(AuthenticationToken authenticationToken, String authenticationCode, Properties caTokenProperties,
            PrivateKey privatekey, PublicKey publickey, PrivateKey privateEncryptionKey, PublicKey publicEncryptionKey,
            Certificate[] caSignatureCertChain, int caId)
            throws CryptoTokenAuthenticationFailedException, IllegalCryptoTokenException, OperatorCreationException, AuthorizationDeniedException {
        // If we don't give an authentication code, perhaps we have autoactivation enabled
        if (StringUtils.isEmpty(authenticationCode)) {
            String msg = intres.getLocalizedMessage("token.authcodemissing", Integer.valueOf(caId));
            log.info(msg);
            throw new CryptoTokenAuthenticationFailedException(msg);
        }
        if (caTokenProperties == null) {
            caTokenProperties = new Properties();
        }

        try {
            // Currently only RSA keys are supported
            KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(null, null);

            // The CAs certificate is first in chain
            Certificate cacert = caSignatureCertChain[0];
            // Assume that the same hash algorithm is used for signing that was used to sign this CA cert
            String signatureAlgorithm = AlgorithmTools.getSignatureAlgorithm(cacert);
            String keyAlg = AlgorithmTools.getKeyAlgorithm(publickey);
            if (keyAlg == null) {
                throw new IllegalCryptoTokenException("Unknown public key type: " + publickey.getAlgorithm() + " (" + publickey.getClass() + ")");
            }

            // import sign keys.
            final Certificate[] certchain = new Certificate[1];
            certchain[0] = CertTools.genSelfCert("CN=SignatureKeyHolder", 36500, null, privatekey, publickey, signatureAlgorithm, true);

            keystore.setKeyEntry(CAToken.SOFTPRIVATESIGNKEYALIAS, privatekey, null, certchain);

            // generate enc keys.
            // Encryption keys must be RSA still
            final String encryptionAlgorithm = AlgorithmTools.getEncSigAlgFromSigAlg(signatureAlgorithm);
            keyAlg = AlgorithmTools.getKeyAlgorithmFromSigAlg(encryptionAlgorithm);
            final String enckeyspec = "2048";
            KeyPair enckeys = null;
            if (publicEncryptionKey == null || privateEncryptionKey == null) {
                enckeys = KeyTools.genKeys(enckeyspec, keyAlg);
            } else {
                enckeys = new KeyPair(publicEncryptionKey, privateEncryptionKey);
            }
            // generate dummy certificate
            certchain[0] = CertTools.genSelfCert("CN=EncryptionKeyHolder", 36500, null, enckeys.getPrivate(), enckeys.getPublic(),
                    encryptionAlgorithm, true);
            keystore.setKeyEntry(CAToken.SOFTPRIVATEDECKEYALIAS, enckeys.getPrivate(), null, certchain);

            // Set the token properties
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);

            // Write the keystore to byte[] that we can feed to crypto token factory
            final char[] authCode = authenticationCode.toCharArray();
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keystore.store(baos, authCode);

            // Now we have the PKCS12 keystore, from this we can create the CAToken
            final Properties cryptoTokenProperties = new Properties();
            int cryptoTokenId;
            try {
                cryptoTokenId = createCryptoTokenWithUniqueName(authenticationToken, "ImportedCryptoToken" + caId, SoftCryptoToken.class.getName(),
                        cryptoTokenProperties, baos.toByteArray(), authCode);
            } catch (NoSuchSlotException e1) {
                throw new RuntimeException("Attempte to define a slot for a soft crypto token. This should not happen.");
            }
            final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
            // If this is a CVC CA we need to find out the sequence
            String sequence = CAToken.DEFAULT_KEYSEQUENCE;
            if (cacert instanceof CardVerifiableCertificate) {
                CardVerifiableCertificate cvccacert = (CardVerifiableCertificate) cacert;
                log.debug("Getting sequence from holderRef in CV certificate.");
                try {
                    sequence = cvccacert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
                } catch (NoSuchFieldException e) {
                    log.error("Can not get sequence from holderRef in CV certificate, using default sequence.");
                }
            }
            log.debug("Setting sequence " + sequence);
            catoken.setKeySequence(sequence);
            log.debug("Setting default sequence format " + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
            catoken.setSignatureAlgorithm(signatureAlgorithm);
            catoken.setEncryptionAlgorithm(encryptionAlgorithm);
            return catoken;
        } catch (KeyStoreException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (CertificateException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (IOException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (IllegalStateException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (CryptoTokenOfflineException e) {
            throw new IllegalCryptoTokenException(e);
        }
    } // importKeys

    @Override
    public void importCAFromHSM(AuthenticationToken authenticationToken, String caname, Certificate[] signatureCertChain, String catokenpassword,
            String catokenclasspath, String catokenproperties) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            IllegalCryptoTokenException, AuthorizationDeniedException, CAExistsException, CAOfflineException, NoSuchSlotException {
        Certificate cacert = signatureCertChain[0];
        int caId = StringTools.strip(CertTools.getSubjectDN(cacert)).hashCode();
        Properties caTokenProperties = CAToken.getPropertiesFromString(catokenproperties);
        // Create the CryptoToken
        int cryptoTokenId = createCryptoTokenWithUniqueName(authenticationToken, "ImportedCryptoToken" + caId, PKCS11CryptoToken.class.getName(),
                caTokenProperties, null, catokenpassword.toCharArray());
        final CAToken catoken = new CAToken(cryptoTokenId, caTokenProperties);
        // Set a lot of properties on the crypto token

        // If this is a CVC CA we need to find out the sequence
        String signatureAlgorithm = AlgorithmTools.getSignatureAlgorithm(cacert);
        String sequence = CAToken.DEFAULT_KEYSEQUENCE;
        if (cacert instanceof CardVerifiableCertificate) {
            CardVerifiableCertificate cvccacert = (CardVerifiableCertificate) cacert;
            log.debug("Getting sequence from holderRef in CV certificate.");
            try {
                sequence = cvccacert.getCVCertificate().getCertificateBody().getHolderReference().getSequence();
            } catch (NoSuchFieldException e) {
                log.error("Can not get sequence from holderRef in CV certificate, using default sequence.");
            }
        }
        log.debug("Setting sequence " + sequence);
        catoken.setKeySequence(sequence);
        log.debug("Setting default sequence format " + StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        catoken.setSignatureAlgorithm(signatureAlgorithm);
        // Encryption keys must be RSA still
        String encryptionAlgorithm = AlgorithmTools.getEncSigAlgFromSigAlg(signatureAlgorithm);
        catoken.setEncryptionAlgorithm(encryptionAlgorithm);
        // Identify the key algorithms for extended CA services, OCSP, CMS
        String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(cacert.getPublicKey());
        String keySpecification = AlgorithmTools.getKeySpecification(cacert.getPublicKey());
        if (keyAlgorithm == null || keyAlgorithm == AlgorithmConstants.KEYALGORITHM_RSA) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            keySpecification = "2048";
        }
        // Do the general import
        importCA(authenticationToken, caname, catokenpassword, signatureCertChain, catoken, keyAlgorithm, keySpecification);
    }

    /** Wrapper for CryptoToken creation that tries to find a unique CryptoTokenName
     * @throws NoSuchSlotException if no slot with the given label could be found
     */
    private int createCryptoTokenWithUniqueName(AuthenticationToken authenticationToken, String basename, String className,
            Properties cryptoTokenProperties, byte[] data, char[] authCode)
            throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, NoSuchSlotException {
        int cryptoTokenId = 0;
        final int maxTriesToFindUnusedCryptoTokenName = 25;
        String postFix = "";
        for (int i = 0; cryptoTokenId == 0 && i < maxTriesToFindUnusedCryptoTokenName; i++) {
            String cryptoTokenName = basename + postFix;
            try {
                cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName, className, cryptoTokenProperties,
                        data, authCode);
            } catch (CryptoTokenNameInUseException e) {
                log.info("CryptoToken with name '" + "' could not be created since the name exists. Trying another name.");
                postFix = "_" + i;
            }
        }
        if (cryptoTokenId == 0) {
            final String msg = "Failed to create a CryptoToken with a unique name after " + maxTriesToFindUnusedCryptoTokenName;
            log.error(msg);
            throw new RuntimeException(msg);
        }
        return cryptoTokenId;
    }

    /**
     * @param keyAlgorithm keyalgorithm for extended CA services, OCSP, CMS. Example AlgorithmConstants.KEYALGORITHM_RSA
     * @param keySpecification keyspecification for extended CA services, OCSP, CMS. Example 2048
     * @throws AuthorizationDeniedException if imported CA was signed by a CA user does not have authorization to.
     * @throws CADoesntExistsException if superCA does not exist
     * @throws CAExistsException if the CA already exists
     * @throws CAOfflineException if CRLs can not be generated because imported CA did not manage to get online
     * @throws CryptoTokenAuthenticationFailedException if authentication to crypto token failed
     * @throws IllegalCryptoTokenException if CA certificate was not self signed, and chain length > 1
     * @throws CryptoTokenOfflineException if crypto token is unavailable.
     *
     */
    private CA importCA(AuthenticationToken admin, String caname, String keystorepass, Certificate[] signatureCertChain, CAToken catoken,
            String keyAlgorithm, String keySpecification) throws CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException,
            IllegalCryptoTokenException, AuthorizationDeniedException, CAExistsException, CAOfflineException {
        // Create a new CA
        int signedby = CAInfo.SIGNEDBYEXTERNALCA;
        int certprof = CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
        String description = "Imported external signed CA";
        Certificate caSignatureCertificate = signatureCertChain[0];
        ArrayList<Certificate> certificatechain = new ArrayList<Certificate>();
        for (int i = 0; i < signatureCertChain.length; i++) {
            certificatechain.add(signatureCertChain[i]);
        }
        if (signatureCertChain.length == 1) {
            if (verifyIssuer(caSignatureCertificate, caSignatureCertificate)) {
                signedby = CAInfo.SELFSIGNED;
                certprof = CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
                description = "Imported root CA";
            } else {
                // A less strict strategy can be to assume certificate signed
                // by an external CA. Useful if admin user forgot to create a
                // full certificate chain in PKCS#12 package.
                log.error("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate) + ": certificate "
                        + CertTools.getSerialNumberAsString(caSignatureCertificate) + " is not self-signed.");
                throw new IllegalCryptoTokenException("Cannot import CA " + CertTools.getSubjectDN(caSignatureCertificate)
                        + ": certificate is not self-signed. Check " + "certificate chain in PKCS#12");
            }
        } else if (signatureCertChain.length > 1) {
            // Assuming certificate chain in forward direction (from target
            // to most-trusted CA). Multiple CA chains can contains the
            // issuer certificate; so only the chain where target certificate
            // is the issuer will be selected.
            for (int caid : caSession.getAllCaIds()) {
                CAInfo superCaInfo = caSession.getCAInfo(admin, caid);
                Iterator<Certificate> i = superCaInfo.getCertificateChain().iterator();
                if (i.hasNext()) {
                    Certificate superCaCert = i.next();
                    if (verifyIssuer(caSignatureCertificate, superCaCert)) {
                        signedby = caid;
                        description = "Imported sub CA";
                        break;
                    }
                }
            }
        }

        CAInfo cainfo = null;
        CA ca = null;
        // We set the validity to be what the CA certificate's validity is. Get the number of days the CA certificate is valid
        int validity = (int) ((CertTools.getNotAfter(caSignatureCertificate).getTime() - CertTools.getNotBefore(caSignatureCertificate).getTime())
                / (24 * 3600 * 1000));
        String encodedValidity = validity + "d";
        List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
        List<Integer> crlpublishers = new ArrayList<Integer>();
        if (caSignatureCertificate instanceof X509Certificate) {
            // Create an X509CA
            // Create and active extended CA Services (CMS).
            // Create and active CMS CA Service.
            extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=CMSCertificate, " + CertTools.getSubjectDN(caSignatureCertificate), "", keySpecification, keyAlgorithm));

            cainfo = new X509CAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, CAConstants.CA_ACTIVE, certprof, encodedValidity,
                    signedby, certificatechain, catoken);
            cainfo.setExpireTime(CertTools.getNotAfter(caSignatureCertificate));
            cainfo.setDescription(description);
            cainfo.setCRLPublishers(crlpublishers);
            cainfo.setExtendedCAServiceInfos(extendedcaservices);
            cainfo.setApprovals(new HashMap<ApprovalRequestType, Integer>());
            ca = new X509CA((X509CAInfo) cainfo);
        } else if (caSignatureCertificate.getType().equals("CVC")) {
            // Create a CVC CA
            // Create the CAInfo to be used for either generating the whole CA
            // or making a request
            cainfo = new CVCCAInfo(CertTools.getSubjectDN(caSignatureCertificate), caname, CAConstants.CA_ACTIVE, certprof, encodedValidity, signedby,
                    certificatechain, catoken);
            cainfo.setExpireTime(CertTools.getNotAfter(caSignatureCertificate));
            cainfo.setDescription(description);
            cainfo.setCRLPublishers(crlpublishers);
            cainfo.setExtendedCAServiceInfos(extendedcaservices);
            cainfo.setApprovals(new HashMap<ApprovalRequestType, Integer>());
            ca = CvcCA.getInstance((CVCCAInfo) cainfo);
        }
        // We must activate the token, in case it does not have the default password
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(catoken.getCryptoTokenId());
        cryptoToken.activate(keystorepass.toCharArray());
        try {
            ca.setCAToken(catoken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalCryptoTokenException(e);
        }
        ca.setCertificateChain(certificatechain);
        if (log.isDebugEnabled()) {
            log.debug("CA-Info: " + catoken.getSignatureAlgorithm() + " " + ca.getCAToken().getEncryptionAlgorithm());
        }
        // Publish CA certificates.
        publishCACertificate(admin, ca.getCertificateChain(), ca.getCRLPublishers(), ca.getSubjectDN());
        // activate External CA Services
        activateAndPublishExternalCAServices(admin, cainfo.getExtendedCAServiceInfos(), ca);
        // Store CA in database.
        caSession.addCA(admin, ca);

        // Create initial CRLs
        try {
            publishingCrlSession.forceCRL(admin, ca.getCAId());
            publishingCrlSession.forceDeltaCRL(admin, ca.getCAId());
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("Newly created CA with ID: " + ca.getCAId() + " was not found in database.");
        }

        return ca;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public byte[] exportCAKeyStore(AuthenticationToken admin, String caname, String keystorepass, String privkeypass, String privateSignatureKeyAlias,
            String privateEncryptionKeyAlias) {
        log.trace(">exportCAKeyStore");
        try {
            final CA thisCa = caSession.getCAForEdit(admin, caname);
            // Make sure we are not trying to export a hard or invalid token
            CAToken thisCAToken = thisCa.getCAToken();
            final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(thisCAToken.getCryptoTokenId());
            if (!(cryptoToken instanceof SoftCryptoToken)) {
                throw new IllegalCryptoTokenException("Cannot export anything but a soft token.");
            }
            // Do not allow export without password protection
            if (StringUtils.isEmpty(keystorepass) || StringUtils.isEmpty(privkeypass)) {
                throw new IllegalArgumentException("Cannot export a token without password protection.");
            }
            // Check authorization
            if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoexportcatoken", caname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                        String.valueOf(thisCa.getCAId()), null, null, details);
                throw new AuthorizationDeniedException(msg);
            }
            // Fetch keys
            final char[] password = keystorepass.toCharArray();
            ((SoftCryptoToken) cryptoToken).checkPasswordBeforeExport(password);
            cryptoToken.activate(password);

            PrivateKey p12PrivateEncryptionKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
            PublicKey p12PublicEncryptionKey = cryptoToken.getPublicKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
            PrivateKey p12PrivateCertSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
            PrivateKey p12PrivateCRLSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            if (!p12PrivateCertSignKey.equals(p12PrivateCRLSignKey)) {
                throw new Exception("Assertion of equal signature keys failed.");
            }
            // Proceed with the export
            byte[] ret = null;
            String format = null;
            if (thisCa.getCAType() == CAInfo.CATYPE_CVC) {
                log.debug("Exporting private key with algorithm: " + p12PrivateCertSignKey.getAlgorithm() + " of format: "
                        + p12PrivateCertSignKey.getFormat());
                format = p12PrivateCertSignKey.getFormat();
                ret = p12PrivateCertSignKey.getEncoded();
            } else {
                log.debug("Exporting PKCS12 keystore");
                format = "PKCS12";
                KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
                keystore.load(null, keystorepass.toCharArray());
                // Load keys into keystore
                Certificate[] certificateChainSignature = thisCa.getCertificateChain().toArray(new Certificate[0]);
                Certificate[] certificateChainEncryption = new Certificate[1];
                // certificateChainSignature[0].getSigAlgName(),
                // generate dummy certificate for encryption key.
                certificateChainEncryption[0] = CertTools.genSelfCertForPurpose("CN=EncryptionKeyHolder", 36500, null, p12PrivateEncryptionKey,
                        p12PublicEncryptionKey, thisCAToken.getEncryptionAlgorithm(), true, X509KeyUsage.keyEncipherment, true);
                log.debug("Exporting with sigAlgorithm " + AlgorithmTools.getSignatureAlgorithm(certificateChainSignature[0]) + "encAlgorithm="
                        + thisCAToken.getEncryptionAlgorithm());
                if (keystore.isKeyEntry(privateSignatureKeyAlias)) {
                    throw new Exception("Key \"" + privateSignatureKeyAlias + "\"already exists in keystore.");
                }
                if (keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    throw new Exception("Key \"" + privateEncryptionKeyAlias + "\"already exists in keystore.");
                }

                keystore.setKeyEntry(privateSignatureKeyAlias, p12PrivateCertSignKey, privkeypass.toCharArray(), certificateChainSignature);
                keystore.setKeyEntry(privateEncryptionKeyAlias, p12PrivateEncryptionKey, privkeypass.toCharArray(), certificateChainEncryption);
                // Return KeyStore as byte array and clean up
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                keystore.store(baos, keystorepass.toCharArray());
                if (keystore.isKeyEntry(privateSignatureKeyAlias)) {
                    keystore.deleteEntry(privateSignatureKeyAlias);
                }
                if (keystore.isKeyEntry(privateEncryptionKeyAlias)) {
                    keystore.deleteEntry(privateEncryptionKeyAlias);
                }
                ret = baos.toByteArray();
            }
            String msg = intres.getLocalizedMessage("caadmin.exportedca", caname, format);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_EXPORTTOKEN, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(thisCa.getCAId()), null, null, details);
            log.trace("<exportCAKeyStore");
            return ret;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorexportca", caname, "PKCS12", e.getMessage());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_EXPORTTOKEN, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null,
                    null, details);
            throw new EJBException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Certificate> getAllCACertificates() {
        final ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        for (final Integer caid : caSession.getAllCaIds()) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caid.intValue(), null, true);
            if (log.isDebugEnabled()) {
                log.debug("Getting certificate chain for CA: " + caInfo.getName() + ", " + caInfo.getCAId());
            }
            final Certificate caCertificate = caInfo.getCertificateChain().iterator().next();
            returnval.add(caCertificate);

        }
        return returnval;
    }

    @Override
    public void activateCAService(AuthenticationToken admin, int caid)
            throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException, CADoesntExistsException {
        // Authorize
        if (!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtoactivatetoken", Integer.valueOf(caid));
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        // Get CA also check authorization for this specific CA
        final CAInfo cainfo = caSession.getCAInfo(admin, caid);
        if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
            log.info(intres.getLocalizedMessage("caadmin.catokenexternal", Integer.valueOf(caid)));
            return;
        }
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
        ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfileForAction(ApprovalRequestType.ACTIVATECA, cainfo, certProfile);
        final ActivateCATokenApprovalRequest ar = new ActivateCATokenApprovalRequest(cainfo.getName(), "", admin, caid,
                ApprovalDataVO.ANY_ENDENTITYPROFILE, approvalProfile, cainfo.getCertificateProfileId());
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN)) {
            int requestId = approvalSession.addApprovalRequest(admin, ar);
            throw new WaitingForApprovalException(intres.getLocalizedMessage("ra.approvalcaactivation"), requestId);
        }
        if (cainfo.getStatus() == CAConstants.CA_OFFLINE) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.activated", caid);
            auditSession.log(EventTypes.CA_SERVICEACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            CA ca = caSession.getCAForEdit(admin, caid);
            ca.setStatus(CAConstants.CA_ACTIVE);
            caSession.editCA(admin, ca, false);
        } else {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errornotoffline", cainfo.getName());
            auditSession.log(EventTypes.CA_SERVICEACTIVATE, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new RuntimeException(detailsMsg);
        }
    }

    private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ACTIVATECATOKEN = {
            new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest.class.getName(), null), };

    @Override
    public void deactivateCAService(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, CADoesntExistsException {
        // Authorize
        if (!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_ACTIVATECA)) {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.notauthorizedtodeactivatetoken",
                    caSession.getCAInfoInternal(caid).getName());
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new AuthorizationDeniedException(detailsMsg);
        }
        final CA ca = caSession.getCAForEdit(admin, caid);
        if (ca.getStatus() == CAConstants.CA_ACTIVE) {
            ca.setStatus(CAConstants.CA_OFFLINE);
            caSession.editCA(admin, ca, false);
            final String detailsMsg = intres.getLocalizedMessage("caadmin.deactivated", caid);
            auditSession.log(EventTypes.CA_SERVICEDEACTIVATE, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
        } else {
            final String detailsMsg = intres.getLocalizedMessage("caadmin.errornotonline", ca.getName());
            auditSession.log(EventTypes.CA_SERVICEDEACTIVATE, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(caid), null, null, detailsMsg);
            throw new RuntimeException(detailsMsg);

        }
    }

    /** Method used to check if certificate profile id exists in any CA. */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<String> getCAsUsingCertificateProfile(final int certificateprofileid) {
        List<String> result = new ArrayList<String>();
        for (final Integer caid : caSession.getAllCaIds()) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caid.intValue(), null, true);
            if (caInfo.getCertificateProfileId() == certificateprofileid) {
                result.add(caInfo.getName());
            }
        }
        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean exitsPublisherInCAs(int publisherid) {
        for (final Integer caid : caSession.getAllCaIds()) {
            for (final Integer pubInt : caSession.getCAInfoInternal(caid).getCRLPublishers()) {
                if (pubInt.intValue() == publisherid) {
                    // We have found a match. No point in looking for more..
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void publishCACertificate(AuthenticationToken admin, Collection<Certificate> certificatechain, Collection<Integer> usedpublishers,
            String caDataDN) throws AuthorizationDeniedException {
        publishCACertificate(admin, certificatechain, usedpublishers, caDataDN, false);
    }

    private void publishCACertificate(AuthenticationToken admin, Collection<Certificate> certificatechain, Collection<Integer> usedpublishers,
            String caDataDN, boolean futureRollover) throws AuthorizationDeniedException {

        Object[] certs = certificatechain.toArray();
        for (int i = 0; i < certs.length; i++) {
            Certificate cert = (Certificate) certs[i];
            String fingerprint = CertTools.getFingerprintAsString(cert);
            // CA fingerprint, figure out the value if this is not a root CA
            String cafp = fingerprint;
            // Calculate the certificate type
            boolean isSelfSigned = CertTools.isSelfSigned(cert);
            int type = CertificateConstants.CERTTYPE_ENDENTITY;
            if (CertTools.isCA(cert)) {
                // this is a CA
                if (isSelfSigned) {
                    type = CertificateConstants.CERTTYPE_ROOTCA;
                } else {
                    type = CertificateConstants.CERTTYPE_SUBCA;
                    // If not a root CA, the next certificate in the chain
                    // should be the CA of this CA
                    if ((i + 1) < certs.length) {
                        Certificate cacert = (Certificate) certs[i + 1];
                        cafp = CertTools.getFingerprintAsString(cacert);
                    } else {
                        // We don't have a chain provided, try to find the CA certificate, assuming that we do not have this certificate in the database
                        List<Certificate> cacerts = certificateStoreSession.findCertificatesBySubject(CertTools.getIssuerDN(cert));
                        if (cacerts != null && cacerts.size() > 0) {
                            for (Certificate cacert : cacerts) {
                                try {
                                    cert.verify(cacert.getPublicKey());
                                    // If we can verify, it was the correct CA cert
                                    cafp = CertTools.getFingerprintAsString(cacert); 
                                    break;
                                } catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException
                                        | SignatureException e) {
                                    log.debug("CA cert could not verify the certificate to import: "+CertTools.getSubjectDN(cacert));
                                }
                            }
                        }
                    }
                }
            } else if (isSelfSigned) {
                // If we don't have basic constraints, but is self signed,
                // we are still a CA, just a stupid CA
                type = CertificateConstants.CERTTYPE_ROOTCA;
            } else {
                // If and end entity, the next certificate in the chain
                // should be the CA of this end entity
                if ((i + 1) < certs.length) {
                    Certificate cacert = (Certificate) certs[i + 1];
                    cafp = CertTools.getFingerprintAsString(cacert);
                }
            }

            String name = "SYSTEMCERT";
            if (type != CertificateConstants.CERTTYPE_ENDENTITY) {
                name = "SYSTEMCA";
            }
            // Store CA certificate in the database if it does not exist
            CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(fingerprint);
            if (certificateDataWrapper == null) {
                // If we don't have it in the database, store it
                long updateTime = System.currentTimeMillis();
                certificateDataWrapper = certificateStoreSession.storeCertificate(admin, cert, name, cafp,
                        futureRollover ? CertificateConstants.CERT_ROLLOVERPENDING : CertificateConstants.CERT_ACTIVE, type,
                        CertificateProfileConstants.NO_CERTIFICATE_PROFILE, EndEntityConstants.NO_END_ENTITY_PROFILE, null, updateTime);
                certificateStoreSession.reloadCaCertificateCache();
            }
            if (usedpublishers != null) {
                publisherSession.storeCertificate(admin, usedpublishers, certificateDataWrapper, null, caDataDN, null);
            }
        }

    }

    @Override
    public void publishCRL(AuthenticationToken admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN,
            boolean doPublishDeltaCRL) throws AuthorizationDeniedException {
        if (usedpublishers == null) {
            return;
        }
        // Store crl in ca CRL publishers.
        if (log.isDebugEnabled()) {
            log.debug("Storing CRL in publishers");
        }
        final String issuerDN = CertTools.getSubjectDN(caCert);
        final String caCertFingerprint = CertTools.getFingerprintAsString(caCert);
        final byte crl[] = crlStoreSession.getLastCRL(issuerDN, false);
        if (crl != null) {
            final int nr = crlStoreSession.getLastCRLInfo(issuerDN, false).getLastCRLNumber();
            publisherSession.storeCRL(admin, usedpublishers, crl, caCertFingerprint, nr, caDataDN);
        }
        if (!doPublishDeltaCRL) {
            return;
        }
        final byte deltaCrl[] = crlStoreSession.getLastCRL(issuerDN, true);
        if (deltaCrl != null) {
            final int nr = crlStoreSession.getLastCRLInfo(issuerDN, true).getLastCRLNumber();
            publisherSession.storeCRL(admin, usedpublishers, deltaCrl, caCertFingerprint, nr, caDataDN);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Set<Integer> getAuthorizedPublisherIds(final AuthenticationToken admin) {
        // Set to use to track all authorized publisher IDs
        final Set<Integer> result = new HashSet<Integer>();
        // Find all publishers, use this set to track unowned publishers
        final Map<Integer, BasePublisher> allPublishers = publisherSession.getAllPublishers();

        //Firstly, weed out all publishers which we lack authorization to
        for (Integer key : new HashSet<Integer>(allPublishers.keySet())) {
            BasePublisher publisher = allPublishers.get(key);
            if (publisher instanceof CustomPublisherContainer) {
                final CustomPublisherContainer custompublisherdata = ((CustomPublisherContainer) publisher);
                if (custompublisherdata.isCustomAccessRulesSupported()) {
                    if (!custompublisherdata.isAuthorizedToPublisher(admin)) {
                        allPublishers.remove(key);
                    }
                }
            }
        }

        //Secondly, find all CAs
        for (final int caId : caSession.getAllCaIds()) {
            CAInfo cainfo = caSession.getCAInfoInternal(caId);
            if (cainfo != null) {
                Collection<Integer> crlPublishers = cainfo.getCRLPublishers();
                if (crlPublishers != null) {
                    final boolean authorizedtoca = caSession.authorizedToCANoLogging(admin, caId);
                    // TODO: Logically getCRLPublishers() should return an empty list if empty, but that's a change for another day
                    for (Integer caPublisherId : crlPublishers) {
                        //This publisher is owned by a CA
                        allPublishers.remove(caPublisherId);
                        // We don't need to log this access (to CA) since it only decides which publishers to display
                        if (authorizedtoca) {
                            //Admin has access to the CA, so return it as a result.
                            result.add(caPublisherId);
                        }
                    }
                }
            }
        }
        //Any remaining publishers must be unowned, so add them in as well.
        result.addAll(allPublishers.keySet());
        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Set<Integer> getAuthorizedKeyValidatorIds(final AuthenticationToken admin) {
        // Find all key validators, use this set to track not owned key validators.
        final Map<Integer, Validator> keyValidators = keyValidatorSession.getAllKeyValidators();
        //Firstly, weed out all key validators which we lack authorization to.
        // Set to use to track all authorized key validator IDs
        final Set<Integer> result = new HashSet<Integer>();
        for (final int caId : caSession.getAllCaIds()) {
            final Collection<Integer> caKeyValidatorIds = caSession.getCAInfoInternal(caId).getValidators();
            if (caKeyValidatorIds != null) {
                final boolean isAuthorizedToCa = caSession.authorizedToCANoLogging(admin, caId);
                for (Integer id : caKeyValidatorIds) {
                    keyValidators.remove(id);
                    // We don't need to log this access (to CA) since it only decides which publishers to display
                    if (isAuthorizedToCa) {
                        //Admin has access to the CA, so return it as a result.
                        result.add(id);
                    }
                }
            }
        }

        //Any remaining key validators must not be owned, so add them in as well.
        result.addAll(keyValidators.keySet());
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String healthCheck() {
        final StringBuilder sb = new StringBuilder();
        final boolean caTokenSignTest = EjbcaConfiguration.getHealthCheckCaTokenSignTest();
        if (log.isDebugEnabled()) {
            log.debug("CaTokenSignTest: " + caTokenSignTest);
        }
        final HashMap<Integer, CryptoToken> cryptoTokenMap = new HashMap<Integer, CryptoToken>();
        for (final Integer caid : caSession.getAllCaIds()) {
            final CAInfo cainfo = caSession.getCAInfoInternal(caid.intValue());
            if (cainfo.getStatus() == CAConstants.CA_ACTIVE && cainfo.getIncludeInHealthCheck()) {
                // Verify that the CA's mapped keys exist and optionally that the test-key is usable
                final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
                CryptoToken cryptoToken = cryptoTokenMap.get(Integer.valueOf(cryptoTokenId));
                if (cryptoToken == null) {
                    cryptoToken = cryptoTokenSession.getCryptoToken(cryptoTokenId);
                    if (cryptoToken != null) {
                        // Cache crypto token lookup locally since multiple CA might use the same and milliseconds count here
                        cryptoTokenMap.put(Integer.valueOf(cryptoTokenId), cryptoToken);
                    }
                }
                final int tokenstatus = cainfo.getCAToken().getTokenStatus(caTokenSignTest, cryptoToken);
                if (tokenstatus == CryptoToken.STATUS_OFFLINE) {
                    sb.append("\nCA: Error CA Token is disconnected, CA Name : ").append(cainfo.getName());
                    log.error("Error CA Token is disconnected, CA Name : " + cainfo.getName());
                }
            }
        }
        return sb.toString();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public ExtendedCAServiceResponse extendedService(AuthenticationToken admin, int caid, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
            CADoesntExistsException, AuthorizationDeniedException, CertificateEncodingException, CertificateException, OperatorCreationException {
        // Get CA that will process request
        final CA ca = caSession.getCA(admin, caid);
        if (log.isDebugEnabled()) {
            log.debug("Extended service with request class '" + request.getClass().getName() + "' called for CA '" + ca.getName() + "'");
        }
        // We do not yet support using a separate crypto token for key recovery, although we have it stored in the key recovery entry
        // so everything is prepared for this possibility.
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
        final ExtendedCAServiceResponse resp = ca.extendedService(cryptoToken, request);
        final String msg = intres.getLocalizedMessage("caadmin.extendedserviceexecuted", request.getClass().getName(), ca.getName());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.CA_EXTENDEDSERVICE, EventStatus.SUCCESS, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(),
                String.valueOf(caid), null, null, details);
        return resp;
    }

    //
    // Private methods
    //

    /**
     * Check if subject certificate is signed by issuer certificate. Used in
     *
     * @see #upgradeFromOldCAKeyStore(Admin, String, byte[], char[], char[], String). This method does a lazy check: if signature verification failed
     *      for any reason that prevent verification, e.g. signature algorithm not supported, method returns false. Author: Marco Ferrante
     *
     * @param subject Subject certificate
     * @param issuer Issuer certificate
     * @return true if subject certificate is signed by issuer certificate
     * @throws java.lang.Exception
     */
    private boolean verifyIssuer(Certificate subject, Certificate issuer) {
        try {
            PublicKey issuerKey = issuer.getPublicKey();
            subject.verify(issuerKey);
            return true;
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Checks the signer validity given a CA object and throws an EJBException to the caller.
     * This should only be called from create and edit CA methods.
     *
     * @param admin administrator calling the method
     * @param signca a CA object of the signer to be checked
     * @throws EJBException embedding a CertificateExpiredException or a CertificateNotYetValidException if the certificate has expired or is not yet
     *             valid
     */
    private void assertSignerValidity(AuthenticationToken admin, CA signca) {
        // Check validity of signers certificate
        final Certificate signcert = signca.getCACertificate();
        try {
            CertTools.checkValidity(signcert, new Date());
        } catch (CertificateExpiredException ce) {
            // Signers Certificate has expired.
            String msg = intres.getLocalizedMessage("signsession.caexpired", signca.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signca.getCAId()), null, null, details);
            throw new EJBException(ce);
        } catch (CertificateNotYetValidException cve) {
            String msg = intres.getLocalizedMessage("signsession.canotyetvalid", signca.getSubjectDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.CA_VALIDITY, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(),
                    String.valueOf(signca.getCAId()), null, null, details);
            throw new EJBException(cve);
        }
    }

    /**
     * Helper method that activates CA services and publisher their certificates, if the services are marked as active
     *
     * @throws AuthorizationDeniedException
     */
    private void activateAndPublishExternalCAServices(AuthenticationToken admin, Collection<ExtendedCAServiceInfo> extendedCAServiceInfos, CA ca)
            throws AuthorizationDeniedException {
        final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        // activate External CA Services
        for (final ExtendedCAServiceInfo info : extendedCAServiceInfos) {
            ArrayList<Certificate> certificates = new ArrayList<Certificate>();
            if (info instanceof CmsCAServiceInfo) {
                try {
                    final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                    ca.initExtendedService(cryptoToken, ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE, ca, cceConfig);
                    final List<Certificate> certPath = ((CmsCAServiceInfo) ca
                            .getExtendedCAServiceInfo(ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE)).getCertificatePath();
                    if (certPath != null) {
                        certificates.add(certPath.get(0));
                    }
                } catch (Exception fe) {
                    String msg = intres.getLocalizedMessage("caadmin.errorcreatecaservice", "CMSCAService");
                    log.error(msg, fe);
                    throw new EJBException(fe);
                }
            }
            // Always store the certificate. Only publish the extended service
            // certificate for active services.
            Collection<Integer> publishers = null;
            if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
                publishers = ca.getCRLPublishers();
            }
            if ((!certificates.isEmpty())) {
                publishCACertificate(admin, certificates, publishers, ca.getSubjectDN());
            }
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushCACache() {
        // Just forward the call, because in CaSession it is only in the local interface and we
        // want to be able to use it from CLI
        caSession.flushCACache();
    }

    @Override
    public void customLog(final AuthenticationToken authenticationToken, final String type, final String caName, final String username, final String certificateSn,
            final String msg, final EventType event) throws AuthorizationDeniedException, CADoesntExistsException {
        // Check authorization to perform custom logging.
        if(!authorizationSession.isAuthorized(authenticationToken, AuditLogRules.LOG_CUSTOM.resource())) {
            throw new AuthorizationDeniedException(intres.getLocalizedMessage("authorization.notauthorizedtoresource", 
                    AuditLogRules.LOG_CUSTOM.resource(), null));
        }
        int caId = 0;
        if(caName != null) {
            final CAInfo cAInfo = caSession.getCAInfo(authenticationToken, caName);
            if (cAInfo == null) {
                throw new CADoesntExistsException("CA with name " + caName + " doesn't exist.");
            } 
            caId = cAInfo.getCAId();
        } else {
            try {
                caId = CertTools.getIssuerDN(((X509CertificateAuthenticationToken) authenticationToken).getCertificate()).hashCode();
            } catch(Exception e) {
                log.debug("Could not get CA by users authentication token: " + authenticationToken.getUniqueId(), e);
            }
        }
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", type + " : " + msg);
        auditSession.log(event, EventStatus.SUCCESS, EjbcaModuleTypes.CUSTOM, EjbcaServiceTypes.EJBCA, authenticationToken.toString(), String.valueOf(caId), certificateSn, username, details);
        if (log.isDebugEnabled()) {
            log.debug("Custom message '" + msg + "'was written to audit log by " + authenticationToken.getUniqueId());
        }
    }
}
