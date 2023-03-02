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

package org.ejbca.core.ejb.upgrade;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.AsyncResult;
import javax.ejb.Asynchronous;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.AccessRulesMigrator;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.approval.ApprovalProfileExistsException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenMetaData;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ca.publisher.upgrade.BasePublisherConverter;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.util.JDBCUtil;

/**
 * The upgrade session bean is used to upgrade the database between EJBCA
 * releases.
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UpgradeSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class UpgradeSessionBean implements UpgradeSessionLocal, UpgradeSessionRemote {

    private static final int PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE = 1000;
    private static final String MSSQL = "mssql";

    private static final Logger log = Logger.getLogger(UpgradeSessionBean.class);

    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("Internal upgrade");

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private AuthorizationSystemSessionLocal authorizationSystemSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @SuppressWarnings("deprecation")
    @EJB
    private LegacyRoleManagementSessionLocal legacyRoleManagementSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;
    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;
    @EJB
    private UpgradeStatusSingletonLocal upgradeStatusSingleton;

    private UpgradeSessionLocal upgradeSession;

    @PostConstruct
    public void ejbCreate() {
    	upgradeSession = sessionContext.getBusinessObject(UpgradeSessionLocal.class);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getLastUpgradedToVersion() {
        return getGlobalUpgradeConfiguration().getUpgradedToVersion();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getLastPostUpgradedToVersion() {
        return getGlobalUpgradeConfiguration().getPostUpgradedToVersion();
    }

    private void setLastUpgradedToVersion(final String version) {
        final GlobalUpgradeConfiguration guc = getGlobalUpgradeConfiguration();
        // (From EJBCA 6.8.0) set the oldest known installation ad-hoc if it was previously unset.
        if(guc.getUpgradedFromVersion() == null) {
            String oldVersion = guc.getUpgradedToVersion();
            if(oldVersion == null) {
                guc.setUpgradedFromVersion(version);
            } else {
                guc.setUpgradedFromVersion(oldVersion);
            }
        }
        guc.setUpgradedToVersion(version);
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, guc);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    private String getUpgradedFromVersion() {
        return getGlobalUpgradeConfiguration().getUpgradedFromVersion();
    }

    private void setLastPostUpgradedToVersion(final String version) {
        final GlobalUpgradeConfiguration guc = getGlobalUpgradeConfiguration();
        guc.setPostUpgradedToVersion(version);
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, guc);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public long getPostUpgradeStarted() {
        return getGlobalUpgradeConfiguration().getPostUpgradeStarted();
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public boolean setPostUpgradeStarted(final long startTimeMs) {
        final GlobalUpgradeConfiguration globalUpgradeConfiguration = getGlobalUpgradeConfiguration();
        if (startTimeMs!=0L && globalUpgradeConfiguration.getPostUpgradeStarted()!=0L) {
            return false;
        }
        globalUpgradeConfiguration.setPostUpgradeStarted(startTimeMs);
        setGlobalUpgradeConfiguration(globalUpgradeConfiguration);
        return true;
    }

    private boolean setPostUpgradeStartedInternal(final long startTimeMs) {
        boolean ret = false;
        try {
            ret = upgradeSession.setPostUpgradeStarted(startTimeMs);
            if (!ret) {
                log.debug("Post upgrade has already been started elsewhere and update prevents start on this node.");
            }
        } catch (RuntimeException e) {
            log.debug("Concurrent persistence update prevents upgrade to start on this node.");
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isEndEntityProfileInCertificateData() {
        return getGlobalUpgradeConfiguration().isEndEntityProfileInCertificateData();
    }

    private void setEndEntityProfileInCertificateData(final boolean value) {
        final GlobalUpgradeConfiguration guc = getGlobalUpgradeConfiguration();
        guc.setEndEntityProfileInCertificateData(value);
        setGlobalUpgradeConfiguration(guc);
    }
    
    private void setCustomCertificateValidityWithSecondsGranularity(final boolean value) {
        final GlobalUpgradeConfiguration guc = getGlobalUpgradeConfiguration();
        guc.setCustomCertificateWithSecondsGranularity(value);
        setGlobalUpgradeConfiguration(guc);
    }
    
    private GlobalUpgradeConfiguration getGlobalUpgradeConfiguration() {
        return (GlobalUpgradeConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
    }
    
    private void setGlobalUpgradeConfiguration(final GlobalUpgradeConfiguration globalUpgradeConfiguration) {
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, globalUpgradeConfiguration);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }
    
    @SuppressWarnings("deprecation")
    private void removeUnidFnrConfigurationFromCmp() throws AuthorizationDeniedException {
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        for(String alias : cmpConfiguration.getAliasList()) {
            if(!StringUtils.isEmpty(cmpConfiguration.getCertReqHandlerClass(alias))) {
                cmpConfiguration.setCertReqHandlerClass(alias, null);
            }
        }
        globalConfigurationSession.saveConfiguration(authenticationToken, cmpConfiguration);

    }


    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public void performPreUpgrade(final boolean isFreshInstallation) {
        try {
            if (isFreshInstallation) {
                // Unlock statedump in new installations
                final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                globalConfig.setStatedumpLockedDown(false);
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfig);
                setEndEntityProfileInCertificateData(true);
                setCustomCertificateValidityWithSecondsGranularity(true);
                // Since we know that this is a brand new installation, no upgrade should be needed
                setLastUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
                setLastPostUpgradedToVersion("7.11.0");
            } else {
                // Ensure that we save currently known oldest installation version before any upgrade is invoked
                if(getLastUpgradedToVersion() != null) {
                    setLastUpgradedToVersion(getLastUpgradedToVersion());
                }
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("AlwaysAllowLocalAuthenticationToken should not have been denied authorization");
        }
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean performUpgrade() {
        final String dbType = DatabaseConfiguration.getDatabaseName();
        final String currentVersion = InternalConfiguration.getAppVersionNumber();
        String last = getLastUpgradedToVersion();
        if (last==null) {
            // Start auto-detection, since no version info was present
            // This auto-detection was added for EJBCA 6.4.0
            if (!checkColumnExists500()) {
                // The CAId column was removed during post upgrade to EJBCA 5.0
                last = "5.0";
                if (globalConfigurationSession.findByConfigurationId(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID)!=null) {
                    last = "6.2.4";
                }
                setLastUpgradedToVersion(last);
                if (!publisherSession.isOldVaPublisherPresent()) {
                    // For all practical purposes, this version can used as post-upgrade version
                    setLastPostUpgradedToVersion("6.4.0");
                }
            } else {
                // We are on EJBCA 4.0 or 3.11 or even earlier
                log.error(
                        "Upgrade from EJBCA prior to version 5.0.0 is forbidden. It is recommended that you upgrade to the intermediate release"
                                + " EJBCA 6.3.2.6 first. Read the EJBCA Upgrade Guide for more information.");
                return false;
            }
        }
        boolean ret = true;
        if (isLesserThan(last, currentVersion)) {
            log.info("Database content version: " + last + ", current application version: " + currentVersion + " -> Starting upgrade.");
            ret = upgradeSession.upgrade(dbType, last, false);
        } else {
            log.info("Database content version: " + last + ", current application version: " + currentVersion + " -> Upgrade is not needed.");
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Asynchronous
    @Override
    public Future<Boolean> startPostUpgrade() {
        log.trace(">startPostUpgrade");
        boolean ret = false;
        if (setPostUpgradeStartedInternal(System.currentTimeMillis())) {
            try {
                upgradeStatusSingleton.logAppenderAttach(log);
                if (upgradeStatusSingleton.setPostUpgradeInProgressIfDifferent(true)) {
                    try {
                        final String dbType = DatabaseConfiguration.getDatabaseName();
                        final String currentVersion = InternalConfiguration.getAppVersionNumber();
                        final String last = getLastPostUpgradedToVersion();
                        if (isLesserThan(last, currentVersion)) {
                            log.info("Database content version: " + last + ", current application version: " + currentVersion + " -> Starting post-upgrade.");
                            ret = upgradeSession.upgrade(dbType, last, true);
                        } else {
                            log.info("Database content version: " + last + ", current application version: " + currentVersion + " -> Post-upgrade is not needed.");
                            ret = true;
                        }
                    } finally {
                        upgradeStatusSingleton.resetPostUpgradeInProgress();
                    }
                } else {
                    log.info("Preventing start of post-upgrade background tasks since it has already been started on this cluster node.");
                }
            } catch (RuntimeException e) {
                // Since this is invoked asynchronously the calling client might no longer be around to receive the "result"
                log.error("Unexpected error from post-upgrade: " + e.getMessage(), e);
            } finally {
                setPostUpgradeStartedInternal(0L);
                upgradeStatusSingleton.logAppenderDetach(log);
            }
        } else {
            log.info("Preventing start of post-upgrade background tasks since it has already been started by a cluster node.");
        }
        log.trace("<startPostUpgrade");
        return new AsyncResult<Boolean>(ret);
    }

    @Override
    public boolean upgrade(String dbtype, String oldVersion, boolean isPost) {
        try {
            log.debug("Upgrading from version=" + oldVersion);
            if (isPost) {
                // TODO: We might want to check that upgrade has run ok before allowing this.
                // ...on the other hand... we wont allow it via the GUI so it might be good to be able to force upgrade retries
                return postUpgrade(oldVersion, dbtype);
            } else {
                return upgrade(dbtype, oldVersion);
            }
        } catch (RuntimeException e) {
        	// We want to log in server.log so we can analyze the error
            log.error("Error thrown during upgrade: ", e);
            throw e;
        } finally {
            log.trace("<upgrade()");
        }
    }

    private boolean upgrade(String dbtype, String oldVersion) {
    	log.debug(">upgrade from version: "+oldVersion+", with dbtype: "+dbtype);
        if (isLesserThan(oldVersion, "5.0.0")) {
            log.error(
                    "Upgrading from EJBCA prior to version 5.0.0 is forbidden. You must upgrade to the intermediate release EJBCA 6.3.2.6 first. Read the EJBCA Upgrade Guide for more information.");
            return false;
        }
        if (isLesserThan(oldVersion, "6.0")) {
            // Check and upgrade if this is the first time we start an instance that was previously an stand-alone VA
            ocspResponseGeneratorSession.adhocUpgradeFromPre60(null);
            setLastUpgradedToVersion("6.0");
        }
        if (isLesserThan(oldVersion, "6.2.4")) {
            try {
                upgradeSession.migrateDatabase624();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.2.4");
        }
        if (isLesserThan(oldVersion, "6.3.1")) {
            // Upgrade the old Validation Authority Publisher in Community Edition (leave it be in Enterprise for the sake of 100% uptime)
            if (!enterpriseEditionEjbBridgeSession.isRunningEnterprise()) {
                publisherSession.adhocUpgradeTo6_3_1_1();
            }
            setLastUpgradedToVersion("6.3.1");
        }
        if (isLesserThan(oldVersion, "6.4")) {
            try {
                upgradeSession.migrateDatabase640();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.4");
        }
        if (isLesserThan(oldVersion, "6.4.2")) {
            try {
                upgradeSession.migrateDatabase642();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.4.2");
        }
        if (isLesserThan(oldVersion, "6.5.1")) {
            try {
                upgradeSession.migrateDatabase651();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.5.1");
        }
        if (isLesserThan(oldVersion, "6.6.0")) {
            try {
                upgradeSession.migrateDatabase660();
            } catch (UpgradeFailedException e) {
                return false;
            }
            if (!isEndEntityProfileInCertificateData()) {
                // Persist mark that this upgrade has not been performed so we can do it in later release (unless the value was set due to this being a fresh installation)
                setEndEntityProfileInCertificateData(false);
            }
            setLastUpgradedToVersion("6.6.0");
        }
        if (isLesserThan(oldVersion, "6.8.0")) {
            try {
                upgradeSession.migrateDatabase680();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.8.0");
        }
        if (isLesserThan(oldVersion, "6.10.1")) {
            try {
                upgradeSession.migrateDatabase6101();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.10.1");
        }
        if (isLesserThan(oldVersion, "6.11.0")) {
            try {
                upgradeSession.migrateDatabase6110();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.11.0");
        }
        if (isLesserThan(oldVersion, "6.12.0")) {
            try {
                upgradeSession.migrateDatabase6120();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.12.0");
        }
        if (isLesserThan(oldVersion, "6.14.0")) {
            try {
                upgradeSession.migrateDatabase6140();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.14.0");
        }
        if (isLesserThan(oldVersion, "6.15.0")) {
            try {
                upgradeSession.migrateDatabase6150();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("6.15.0");
        }
        if (isLesserThan(oldVersion, "7.2.0")) {
            upgradeSession.upgradeCrlStoreAndCertStoreConfiguration720();
            setLastUpgradedToVersion("7.2.0");
        }
        if (isLesserThan(oldVersion, "7.3.0")) {
            upgradeSession.migrateDatabase730();
            setLastUpgradedToVersion("7.3.0");
        }
        if (isLesserThan(oldVersion, "7.8.0")) {
            try {
                upgradeSession.migrateDatabase780();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("7.8.0");
        }

        if (isLesserThan(oldVersion, "7.8.1")) {
            try {
                upgradeSession.migrateDatabase781();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("7.8.1");
        }
        if (isLesserThan(oldVersion, "7.10.0")) {
            try {
                upgradeSession.migrateDatabase7100();
            } catch (UpgradeFailedException e) {
                return false;
            }
            setLastUpgradedToVersion("7.10.0");
        }
        if (isLesserThan(oldVersion, "7.11.0")) {
            try {
                upgradeSession.migrateDatabase7110();
            } catch (UpgradeFailedException e) {
                return false;
            }
        }
        if (isLesserThan(oldVersion, "8.0.0")) {
            try {
                upgradeSession.migrateDatabase800();
            } catch (UpgradeFailedException e) {
                return false;
            }
        }
        setLastUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
        return true;
    }

    private boolean postUpgrade(String oldVersion, String dbtype) {
        log.debug(">post-upgrade from version: "+oldVersion);
        if (isLesserThan(oldVersion, "5.0.0")) {
            log.error(
                    "Post-upgrade from EJBCA prior to version 5.0.0 is forbidden. You must upgrade to the intermediate release EJBCA 6.3.2.6 first. Read the EJBCA Upgrade Guide for more information.");
            return false;
        }
        if (isLesserThan(oldVersion, "6.3.2")) {
            if (!postMigrateDatabase632()) {
                return false;
            }
            setLastPostUpgradedToVersion("6.3.2");
        }
        if (isLesserThan(oldVersion, "6.8.0")) {
            if (!postMigrateDatabase680()) {
                return false;
            }
            setLastPostUpgradedToVersion("6.8.0");
        }
        if (isLesserThan(oldVersion, "6.10.1")) {
            if (!postMigrateDatabase6101()) {
                return false;
            }
            setLastPostUpgradedToVersion("6.10.1");
        }
        if (isLesserThan(oldVersion, "7.2.0")) {
            if (!postMigrateDatabase720()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.2.0");
        }
        if (isLesserThan(oldVersion, "7.4.0")) {
            if (!postMigrateDatabase740()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.4.0");
        }
        if (isLesserThan(oldVersion, "7.8.0")) {
            if (!postMigrateDatabase780()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.8.0");
        }
        if (isLesserThan(oldVersion, "7.8.1")) {
            if (!postMigrateDatabase781()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.8.1");
        }
        if (isLesserThan(oldVersion, "7.10.0")) {
            if (!postMigrateDatabase710()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.10.0");
        }
        if (isLesserThan(oldVersion, "7.11.0")) {
            if (!postMigrateDatabase7110()) {
                return false;
            }
            setLastPostUpgradedToVersion("7.11.0");
        }
        
        // NOTE: If you add additional post upgrade tasks here, also modify isPostUpgradeNeeded() and performPreUpgrade()
        //setLastPostUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
        return true;
    }

    /**
     * Update all EndEntityProfiles.
     *
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    private boolean postMigrateDatabase781() {
        log.info("Starting post upgrade to 7.8.1");
        List<Integer> ids;
        try {
            Query query = entityManager.createQuery("SELECT eepd.id FROM EndEntityProfileData eepd");
            ids = query.getResultList();
        } catch (Exception e) {
            log.error("An error occurred when updating data in database table 'EndEntityProfileData': " + e);
            return false;
        }

        for(Integer id: ids) {
            final String eepName = endEntityProfileSession.getEndEntityProfileName(id);
            try {
                EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(id);
                if (EeProfileUpdgaderFor781.shouldUpdate(eep)) {
                    EeProfileUpdgaderFor781.update(eep);
                    endEntityProfileSession.changeEndEntityProfile(authenticationToken, eepName, eep);
                }
            } catch (AuthorizationDeniedException | EndEntityProfileNotFoundException e) {
                log.error("An error occurred when updating end entity profile '"+ eepName + "': " + e);
                return false;
            }
        }
        log.info("Post upgrade to 7.8.1 complete.");
        return true;
    }
    
    /**
     * Copies the fields 
     * 
     *  identifier, 
     *  identifierType, 
     *  status and
     *  expires 
     *  
     *  from the AcmeAuthorizationData rawData into the separate DB columns for indexing.
     */
    @SuppressWarnings("unchecked")
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    private boolean postMigrateDatabase710() {
        log.info("Starting post upgrade to 7.10.0");
        
        List<String> accountIds;
        try {
            final Query query = entityManager.createQuery("SELECT a.accountId FROM AcmeAccountData a");
            accountIds = (List<String>) query.getResultList();
        } catch (Exception e) {
            log.error("An error occurred when updating data in database table 'AcmeAuthorizationData': " + e);
            return false;
        }
        
        // two steps to upgrade all authorizations associated with an ACME account:
        // 1. upgrade authorizations of 'normal' orders (have an orderId), or processed pre-authorizations (get an orderId during processing)
        // 2. upgrade pre-authorization which still do not have an orderId.
        
        if (accountIds != null && accountIds.size() > 0) {
            for (String accountId : accountIds) {
                log.info("Upgrade authorizations for ACME account '" + accountId + "'.");
                // step 1:
                final List<String> orderIds;
                try {
                    final Query query = entityManager.createQuery("SELECT o.orderId FROM AcmeOrderData o WHERE o.accountId = :accountId");
                    query.setParameter("accountId", accountId);
                    orderIds = (List<String>) query.getResultList();
                } catch (Exception e) {
                    log.error("An error occurred when updating data in database table 'AcmeAuthorizationData': " + e);
                    return false;
                }
                
                if (orderIds != null && orderIds.size() > 0) {
                    for (String orderId : orderIds) {
                        List<String> rawDatas;
                        try {
                            Query query = entityManager.createQuery("SELECT a.rawData FROM AcmeAuthorizationData a WHERE a.accountId = :accountId and a.orderId = :orderId");
                            query.setParameter("accountId", accountId);
                            query.setParameter("orderId", orderId);
                            rawDatas = (List<String>) query.getResultList();
                            for (String rawData : rawDatas) {
                                upgradeAcmeAuthorization(null, rawData);
                            }
                        } catch (Exception e) {
                            log.error("An error occurred when updating data in database table 'AcmeAuthorizationData': " + e);
                            return false;
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No ACME orders for account with ID '" + accountId + " found'");
                    }
                }
                
                // step 2: pre-authorization which still do not have an orderId.
                final List<String> preAuthorizationIds;
                try {
                    final Query query = entityManager.createQuery("SELECT a.authorizationId FROM AcmeAuthorizationData a WHERE a.accountId = :accountId and a.orderId is null");
                    query.setParameter("accountId", accountId);
                    preAuthorizationIds = (List<String>) query.getResultList();
                } catch (Exception e) {
                    log.error("An error occurred when updating data in database table 'AcmeAuthorizationData': " + e);
                    return false;
                }
                
                if (preAuthorizationIds != null && preAuthorizationIds.size() > 0) {
                    for (String preAuthorizationId : preAuthorizationIds) {
                        try {
                            final Query query = entityManager.createQuery("SELECT a.rawData FROM AcmeAuthorizationData a WHERE a.authorizationId = :authorizationId");
                            query.setParameter("authorizationId", preAuthorizationId);
                            final String rawData = (String) query.getSingleResult();
                            
                            upgradeAcmeAuthorization(preAuthorizationId, rawData);
                        } catch (Exception e) {
                            log.error("An error occurred when updating data in database table 'AcmeAuthorizationData': " + e);
                            return false;
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No ACME pre-authorizations for account with ID '" + accountId + " found'");
                    }
                }
            }
        } else {
            log.info("No ACME accounts or certificates found in the system. No upgrade for ACME authorizations required.");
        }
        
        log.info("Post upgrade to 7.10.0 complete.");
        return true;
    }
    
    @SuppressWarnings("unchecked")
    private void upgradeAcmeAuthorization(String authorizationId, final String rawData) {
        try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(rawData.getBytes(StandardCharsets.UTF_8)));) {
            final LinkedHashMap<Object, Object> dataMap = new Base64GetHashMap((Map<?, ?>) decoder.readObject());
            final String identifier = (String) dataMap.get("acmeIdentifierValue");
            final String identifierType = (String) dataMap.get("acmeIdentifierType");
            final String status = (String) dataMap.get("status");
            final Long expires = (Long) dataMap.get("expires");
            if (authorizationId == null) {
                authorizationId = (String) dataMap.get("authorizationId");
            }
            
            final Query query = entityManager.createQuery("UPDATE AcmeAuthorizationData a SET a.identifier = :identifier, a.identifierType = :identifierType, a.status = :status, a.expires = :expires WHERE a.authorizationId = :authorizationId");
            query.setParameter("identifier", identifier);
            query.setParameter("identifierType", identifierType);
            query.setParameter("status", status);
            query.setParameter("expires", expires);
            query.setParameter("authorizationId", authorizationId);
            int rowsUpdated = query.executeUpdate();
            if (rowsUpdated == 1) {
                log.trace("Upgraded ACME authorization with ID '" + authorizationId + "', status='" + status + "', identifier='" + identifier + "'.");
            } else {
                // Should never happen.
                throw new IOException("Found '" + rowsUpdated + " for ACME authorizations with ID '" + authorizationId + "'.");
            }
        } catch (Exception e) {
            final String msg = "Failed to upgrade AcmeAuthorizationData in database: " + e.getMessage();
            log.error(msg + ". Data:\n" + rawData);
            throw new IllegalStateException(msg, e);
        }
    }
    
    private boolean postMigrateDatabase780() {
        // post upgrade is only allowed when all OAuth providers have audience values.
        OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession
                .getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        boolean missingAudienceFound = false;
        for (OAuthKeyInfo oAuthKeyInfo : oAuthConfiguration.getOauthKeys().values()) {
            if (!oAuthKeyInfo.isAudienceCheckDisabled() && (oAuthKeyInfo.getAudience() == null || oAuthKeyInfo.getAudience().trim().isEmpty())) {
                log.error("OAuth configuration " + oAuthKeyInfo.getLabel()
                        + " has an empty Audience value.  This is less secure and should be set."
                        + "  Go to \"System Configuration / Trusted OAuth Providers\" and configure Audience for "
                        + oAuthKeyInfo.getLabel() + " or de-select Enable Audience Check (not recommended).");
                missingAudienceFound = true;
            }
        }

        return !missingAudienceFound;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean isPostUpgradeNeeded() {
        return isLesserThan(getLastPostUpgradedToVersion(), "7.11.0");
    }

    /**
     * Upgrade access rules such that every role that already has access to /system_functionality/edit_systemconfiguration
     * will also have access to the new access rule /system_functionality/edit_available_extended_key_usages
     *
     * @return true if the upgrade was successful and false otherwise
     */
    @SuppressWarnings("deprecation")
    private boolean addEKUAndCustomCertExtensionsAccessRulestoRoles() {
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
        		Arrays.asList(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()),
                Arrays.asList(StandardRules.EKUCONFIGURATION_EDIT.resource(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource()), false);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        return true;
    }

    private void importExtendedKeyUsagesFromFile() {
        final URL url = ConfigurationHolder.class.getResource("/conf/extendedkeyusage.properties");
        AvailableExtendedKeyUsagesConfiguration ekuConfig;
        if (url == null) {
            // Create using the default template of the current version if no such file exists
            ekuConfig = (AvailableExtendedKeyUsagesConfiguration)
                    globalConfigurationSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        } else {
            ekuConfig = new AvailableExtendedKeyUsagesConfiguration(false);
            final Configuration conf = ConfigurationHolder.instance();
            final String ekuname = "extendedkeyusage.name.";
            final String ekuoid = "extendedkeyusage.oid.";
            int j=0;
            for (int i = 0; i < 255; i++) {
                final String oid = conf.getString(ekuoid+i);
                if (oid != null) {
                    String name = conf.getString(ekuname+i);
                    if (name != null) {
                        // A null value in the properties file means that we should not use this value, so set it to null for real
                        if (!name.equalsIgnoreCase("null")) {
                            // Set the untranslated name (since the translation is actually only available in the Admin GUI)
                            ekuConfig.addExtKeyUsage(oid, name);
                            j++;
                        }
                    } else {
                        log.error("Found extended key usage oid "+oid+", but no name defined. Not adding to list of extended key usages.");
                    }
                }
                // No eku with a certain number == continue trying next, we will try 0-255.
            }
            if(log.isDebugEnabled()) {
                log.debug("Read " + j + " extended key usages from the configurations file");
            }
        }
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, ekuConfig);
        } catch (AuthorizationDeniedException e) {
            log.error("Received an AuthorizationDeniedException even though AlwaysAllowLocalAuthenticationToken is used. " + e.getLocalizedMessage());
        }
    }

    /**
     * This method adds read-only rules that were created for the new read-only admin in https://jira.primekey.se/browse/ECA-4344. It makes sure that any roles which previously
     * had access to the affected resources retain read rights (in case those roles should be restricted as a result of this ticket).
     *
     * All access has been made more granular, so performing this step post-upgrade is safe.
     *
     *
     * The exact changes performed are documented in the UPGRADE document.
     * @throws UpgradeFailedException if upgrade fails.
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    private void addReadOnlyRules640() throws UpgradeFailedException {
        // Roles with access to /ca_functionality/basic_functions/activate_ca or just /ca_functionality/ (+recursive)
        // should be given access to /ca_functionality/view_ca
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.CAFUNCTIONALITY.resource(),
                Arrays.asList(AccessRulesConstants.REGULAR_ACTIVATECA), Arrays.asList(StandardRules.CAVIEW.resource()), false);
        // Roles with access to /ca_functionality/edit_certificate_profiles should be given access to /ca_functionality/view_certificate_profiles
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.CAFUNCTIONALITY.resource(),
                Arrays.asList(StandardRules.CERTIFICATEPROFILEEDIT.resource()), Arrays.asList(StandardRules.CERTIFICATEPROFILEVIEW.resource()), false);
        // Roles with access to /ca_functionality/edit_publisher should be given /ca_functionality/view_publisher
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.CAFUNCTIONALITY.resource(),
                Arrays.asList(AccessRulesConstants.REGULAR_EDITPUBLISHER), Arrays.asList(AccessRulesConstants.REGULAR_VIEWPUBLISHER), false);
        // Roles with access to /ra_functionality/edit_end_entity_profiles should be given /ra_functionality/view_end_entity_profiles
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, AccessRulesConstants.REGULAR_RAFUNCTIONALITY,
                Arrays.asList(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES), Arrays.asList(AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES), false);
        // Roles with access to "/" (non-recursive) should be given /services/edit, /services/view and /peer/view (+recursive)
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), Arrays.asList(AccessRulesConstants.SERVICES_EDIT, AccessRulesConstants.SERVICES_VIEW), false);
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.ROLE_ROOT.resource()), Arrays.asList(AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW), true);
        // Roles with access to /internalkeybinding should be given /internalkeybinding/view (+recursive)
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(InternalKeyBindingRules.BASE.resource()), Arrays.asList(InternalKeyBindingRules.VIEW.resource()), true);
    }

    /**
     * Adds the access rules defined in https://jira.primekey.se/browse/ECA-4463
     *
     * These are:   View rules for system configuration, EKU config and CCE config
     *
     * Any roles which matched the previous auditor role, or which had edit access to the above will be given view access.
     * @throws UpgradeFailedException
     *
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    private void addReadOnlyRules642() throws UpgradeFailedException {
        // If role is the old auditor from 6.4.0, grant new view rights
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(), Arrays.asList(
                AccessRulesConstants.ROLE_ADMINISTRATOR,
                AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                AuditLogRules.VIEW.resource(),
                InternalKeyBindingRules.VIEW.resource(),
                StandardRules.CAVIEW.resource(),
                StandardRules.CERTIFICATEPROFILEVIEW.resource(),
                StandardRules.APPROVALPROFILEVIEW.resource(),
                CryptoTokenRules.VIEW.resource(),
                AccessRulesConstants.REGULAR_VIEWPUBLISHER,
                AccessRulesConstants.SERVICES_VIEW,
                AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES,
                AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW,
                StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                StandardRules.EKUCONFIGURATION_VIEW.resource(),
                StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(),
                StandardRules.VIEWROLES.resource(),
                AccessRulesConstants.REGULAR_VIEWENDENTITY
                ), Arrays.asList(
                        StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                        StandardRules.EKUCONFIGURATION_VIEW.resource(),
                        StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(),
                        StandardRules.VIEWROLES.resource(),
                        AccessRulesConstants.REGULAR_VIEWENDENTITY
                        ), false);
        // Other cases where we should grant additional access.
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.SYSTEMCONFIGURATION_EDIT.resource()), Arrays.asList(StandardRules.SYSTEMCONFIGURATION_VIEW.resource()), false);
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.EKUCONFIGURATION_EDIT.resource()), Arrays.asList(StandardRules.EKUCONFIGURATION_VIEW.resource()), false);
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource()), Arrays.asList(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource()), false);
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.ROLE_ROOT.resource(),
                Arrays.asList(StandardRules.EDITROLES.resource()), Arrays.asList(StandardRules.VIEWROLES.resource()), false);
    }

    /**
     * EJBCA 6.3.1.1 moves the VA Publisher from Community to Enterprise, changing its baseclass in the process for Enterprise users.
     * This method will fail gracefully if user is not running Enterprise. It will also upgrade any placeholder publishers from 6.3.1.1 Community
     * if so required.
     *
     * @return true if the upgrade was successful
     */
    private boolean postMigrateDatabase632() {
        if(!enterpriseEditionEjbBridgeSession.isRunningEnterprise()) {
            log.error("Upgrade procedure to 6.3.2 can only be run on EJBCA Enterprise.");
            return true; // Fail gracefully and pretend it was ok.
        }
        log.error("(this is not an error) Starting post upgrade to 6.3.2");
        //Find all publishers, make copies of them using the new publisher class.
        Map<Integer, BasePublisher> allPublishers = publisherSession.getAllPublishers();
        Map<Integer, String> publisherNames = publisherSession.getPublisherIdToNameMap();
        BasePublisherConverter publisherFactory;
        try {
            publisherFactory = (BasePublisherConverter) Class.forName("org.ejbca.va.publisher.EnterpriseValidationAuthorityPublisherFactoryImpl").getDeclaredConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
            //Shouldn't happen since we've already checked that we're running Enterprise
            throw new IllegalStateException(e);
        }
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.postMigrateDatabase631"));

        for(Integer publisherId : allPublishers.keySet()) {
            BasePublisher newPublisher = publisherFactory.createPublisher(allPublishers.get(publisherId));
            if (newPublisher != null) {
                try {
                    String publisherName = publisherNames.get(publisherId);
                    log.info("Upgrading publisher: " + publisherName);
                    publisherSession.changePublisher(admin, publisherName, newPublisher);
                } catch (AuthorizationDeniedException e) {
                    throw new IllegalStateException("Always allow token was not given access to publishers.", e);
                }
            }
        }
        return true;
    }

    /**
     * EJBCA 6.2.4 introduced default responder configuration in the database.
     *
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase624() throws UpgradeFailedException {
        // Check if there the default responder has been set. If not, try setting it using the old value.
        GlobalOcspConfiguration globalConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        if (StringUtils.isEmpty(globalConfiguration.getOcspDefaultResponderReference())) {
            globalConfiguration.setOcspDefaultResponderReference(OcspConfiguration.getDefaultResponderId());
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                throw new UpgradeFailedException(e);
            }
            globalConfigurationSession.flushConfigurationCache(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        }
        log.error("(This is not an error) Completed upgrade procedure to 6.2.4");
    }

    /**
     * EJBCA 6.4.0 introduces new sun rules to System Configuration in regards to Custom OIDs and EKUs.
     *
     * Access rules have also been added for read only rights to parts of the GUI.
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase640() throws UpgradeFailedException {
        //First add access rules for handling custom OIDs to any roles which previous had access to system configuration
        // Add the new access rule /system_functionality/edit_available_extended_key_usages to every role that already has the access rule /system_functionality/edit_systemconfiguration
        addEKUAndCustomCertExtensionsAccessRulestoRoles();
        importExtendedKeyUsagesFromFile();
        // Next add access rules for the new audit role template, allowing easy restriction of resources where needed.
        addReadOnlyRules640();
        log.error("(This is not an error) Completed upgrade procedure to 6.4.0");
    }

    /**
     * EJBCA 6.4.2:
     *
     * 1.   Adds view rules to System Configuration, EKU Configuration and Certificate Extension Configuration. Any roles with edit rights to those pages, or which match the Auditor role
     *      from 6.4.0 will be automatically upgraded.
     * 2.   Adds view rules to Roles. Any roles with edit rights roles, or which match the Auditor role from 6.4.0 will be automatically upgraded.
     *
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase642() throws UpgradeFailedException {
        addReadOnlyRules642();
        log.error("(This is not an error) Completed upgrade procedure to 6.4.2");
    }

    /**
     * EJBCA 6.5.1:
     *
     * This upgrade only affects CMP aliases:
     * 1.   End entity profiles will be referred to by ID instead of by name. In consideration of 100% uptime requirements, the value
     *      ra.endentityprofile is replaced by ra.endentityprofileid, allowing legacy configurations to keep using the old value.
     *
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase651() throws UpgradeFailedException {
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        for(final String cmpAlias : cmpConfiguration.getAliasList()) {
            // Avoid aliases that may already have been upgraded
            if(StringUtils.isEmpty(cmpConfiguration.getRAEEProfile(cmpAlias))) {
                @SuppressWarnings("deprecation")
                String endEntityProfileName = cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE, cmpAlias);
                if (!StringUtils.isEmpty(endEntityProfileName)) {
                    try {
                        cmpConfiguration.setRAEEProfile(cmpAlias,
                                Integer.toString(endEntityProfileSession.getEndEntityProfileId(endEntityProfileName)));
                    } catch (EndEntityProfileNotFoundException e) {
                        //Fail gracefully if a CMP alias already is in an error state
                        log.error("CMP alias " + cmpAlias + " could not be upgraded. It refers by name to End Entity Profile " + endEntityProfileName
                                + ", which does not appear to exist. Value has instead been set to 1 (EMPTY). Please review this profile after upgrade.");
                        cmpConfiguration.setRAEEProfile(cmpAlias, CmpConfiguration.DEFAULT_RA_EEPROFILE);
                    }
                } else {
                    //Could be a client alias, we still need to set a default value though
                    cmpConfiguration.setRAEEProfile(cmpAlias, CmpConfiguration.DEFAULT_RA_EEPROFILE);
                }
            }
        }
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, cmpConfiguration);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
        log.error("(This is not an error) Completed upgrade procedure to 6.5.1");
    }

    /**
     * EJBCA 6.6.0:
     *
     * 1.   Adds new access rules for approval profiles
     * 2.   If CA or certificate profiles require Approvals, create a new Approval Profile matching those settings and convert to using that
     *
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase660() throws UpgradeFailedException {
        log.debug("migrateDatabase660: Upgrading roles with approval rules");
        // Any roles with access to /ca_functionality/view_certificate_profiles should be given /ca_functionality/view_approval_profiles
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.CAFUNCTIONALITY.resource(),
                Arrays.asList(StandardRules.CERTIFICATEPROFILEVIEW.resource()), Arrays.asList(StandardRules.APPROVALPROFILEVIEW.resource()), false);
        // Any roles with access to /ca_functionality/edit_certificate_profiles should be given /ca_functionality/edit_approval_profiles
        legacyRoleManagementSession.addAccessRuleDataToRolesWhenAccessIsImplied(authenticationToken, StandardRules.CAFUNCTIONALITY.resource(),
                Arrays.asList(StandardRules.CERTIFICATEPROFILEEDIT.resource()), Arrays.asList(StandardRules.APPROVALPROFILEEDIT.resource()), false);
        // Create AccumulativeApprovalProfile for all CA's and Certificate Profiles running approvals
        //Sort cache by the number of approvals
        Map<Integer, Integer> approvalProfileCache = new HashMap<>();
        Map<Integer, Integer> approvalPartitionCache = new HashMap<>();
        //Add approval profiles to all CAs with approvals
        try {
            log.debug("migrateDatabase660: Upgrading CAs with approval profiles");
            for (int caId : caSession.getAllCaIds()) {
                try {
                    CACommon ca = caSession.getCAForEdit(authenticationToken, caId);
                    int numberOfRequiredApprovals = ca.getNumOfRequiredApprovals();
                    //Verify that the CA is in need of an approval profile...
                    if (ca.getApprovalProfile() == -1 && ca.getApprovalSettings().size() > 0) {
                        //Maybe this profile has already been created?
                        if (approvalProfileCache.containsKey(Integer.valueOf(numberOfRequiredApprovals))) {
                            //Indeed it has!
                            ca.setApprovalProfile(approvalProfileCache.get(numberOfRequiredApprovals));
                            caSession.editCA(authenticationToken, ca, true);
                        } else {
                            //None found! Let's create one!
                            String name = "Require " + numberOfRequiredApprovals + " Approval" + (numberOfRequiredApprovals > 1 ? "s" : "");
                            AccumulativeApprovalProfile newProfile = new AccumulativeApprovalProfile(name);
                            try {
                                newProfile.setNumberOfApprovalsRequired(numberOfRequiredApprovals);
                            } catch (PropertyValidationException e1) {
                                log.info("Attempted to upgrade an approval profile with negative value (" + numberOfRequiredApprovals + "). Setting 0 instead.");
                                try {
                                    newProfile.setNumberOfApprovalsRequired(0);
                                } catch (PropertyValidationException e) {
                                    throw new IllegalStateException(e);
                                }
                            }
                            addApprovalNotification(newProfile);
                            try {
                                int newProfileId = approvalProfileSession.addApprovalProfile(authenticationToken, newProfile);
                                approvalProfileCache.put(numberOfRequiredApprovals, newProfileId);
                                approvalPartitionCache.put(numberOfRequiredApprovals, newProfile.getFirstStep().getPartitions().values().iterator().next().getPartitionIdentifier());
                                ca.setApprovalProfile(newProfileId);
                                caSession.editCA(authenticationToken, ca, true);
                            } catch (ApprovalProfileExistsException e) {
                                throw new IllegalStateException("Approval profile was apparently already persisted.", e);
                            }
                        }
                    }
                } catch (CADoesntExistsException e) {
                    throw new IllegalStateException("CA was not found, in spite of ID just being retrieved", e);
                }
            }
            //Do the same for all certificate profiles (same boilerplate, repeated).
            log.debug("migrateDatabase660: Upgrading Certificate Profiles with approval profiles");
            Map<Integer, CertificateProfile> allCertificateProfiles = certProfileSession.getAllCertificateProfiles();
            for (Integer certificateProfileId : allCertificateProfiles.keySet()) {
                CertificateProfile certificateProfile = allCertificateProfiles.get(certificateProfileId);
                int numberOfRequiredApprovals = certificateProfile.getNumOfReqApprovals();
                //Verify that the Certificate Profile is in need of an approval profile...
                if (certificateProfile.getApprovalProfileID() == -1 && certificateProfile.getApprovalSettings().size() > 0) {
                    //Maybe this profile has already been created?
                    String certificateProfileName = certProfileSession.getCertificateProfileName(certificateProfileId);
                    if (approvalProfileCache.containsKey(Integer.valueOf(numberOfRequiredApprovals))) {
                        //Indeed it has!
                        certificateProfile.setApprovalProfileID(approvalProfileCache.get(numberOfRequiredApprovals));
                        certProfileSession.changeCertificateProfile(authenticationToken, certificateProfileName, certificateProfile);
                    } else {
                        //None found! Let's create one!
                        String name = "Require " + numberOfRequiredApprovals + " approval" + (numberOfRequiredApprovals > 1 ? "s" : "");
                        AccumulativeApprovalProfile newProfile = new AccumulativeApprovalProfile(name);
                        try {
                            newProfile.setNumberOfApprovalsRequired(numberOfRequiredApprovals);
                        } catch (PropertyValidationException e1) {
                            log.info("Attempted to upgrade an approval profile with negative value (" + numberOfRequiredApprovals + "). Setting 0 instead.");
                            try {
                                newProfile.setNumberOfApprovalsRequired(0);
                            } catch (PropertyValidationException e) {
                                throw new IllegalStateException(e);
                            }
                        }
                        addApprovalNotification(newProfile);
                        try {
                            int newProfileId = approvalProfileSession.addApprovalProfile(authenticationToken, newProfile);
                            approvalProfileCache.put(numberOfRequiredApprovals, newProfileId);
                            approvalPartitionCache.put(numberOfRequiredApprovals, newProfile.getFirstStep().getPartitions().values().iterator().next().getPartitionIdentifier());
                            certificateProfile.setApprovalProfileID(newProfileId);
                            certProfileSession.changeCertificateProfile(authenticationToken, certificateProfileName, certificateProfile);
                        } catch (ApprovalProfileExistsException e) {
                            throw new IllegalStateException("Upgrade appears to be happening concurrently.", e);
                        }
                    }
                }
            }

            // An approval now is specific to a partition in a step. Connect previously performed approvals
            // to the newly created partition so that the new code will recognize it. Note that an AccumulativeApprovalProfile
            // only has one step and one partition. The step ID is '0', which is the default step ID in an approval, which
            // is why the step ID in an approval does not need updating the same way as the partition ID needs updating.
            List<ApprovalData> approvalRequests = approvalSession.findWaitingForApprovalApprovalDataLocal();
            if (approvalRequests.isEmpty()) {
                log.debug("migrateDatabase660: No approval requests to upgrade");
            } else {
                log.debug("migrateDatabase660: Upgrading approval requests");
            }
            for(ApprovalData request : approvalRequests) {
                Collection<Approval> approvals = request.getApprovals();
                if(approvals.size() > 0) {
                    final int nrOfRequiredApprovals = request.getRemainingapprovals() + approvals.size();
                    final Integer partitionId = approvalPartitionCache.get(Integer.valueOf(nrOfRequiredApprovals));
                    if (partitionId != null) {
                        // It's an old approval from before 6.6.0, that needs upgrading
                        for (Approval approval : approvals) {
                            approval.setPartitionId(partitionId);
                        }
                        approvalSession.setApprovals(request, approvals);
                    } else {
                        // Might be an approval from 6.6.0, in case the upgrade fails at first and the user adds an approval (in 6.6 or later) before the successful upgrade.
                        // Check that this is really the case
                        boolean error = false;
                        for (Approval approval : approvals) {
                            if (approval.getPartitionId() == 0) { // not from 6.6.0, and can not be upgraded
                                error = true;
                            }
                        }
                        if (error) {
                            log.error("An approval in the approval request with ID " + request.getId() + " could not be upgraded because it could not be mapped to an accumulative approval profile. The approvals in this request have been deleted");
                            approvalSession.setApprovals(request, new ArrayList<Approval>());
                        }
                    }
                }
            }

        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("AlwaysAllowToken was denied access", e);
        }
        log.error("(This is not an error) Completed upgrade procedure to 6.6.0");
    }

    /**
     * EJBCA 6.8.0:
     *
     * 1.   Converts AdminGroupData, AccessRuleData and AdminEntityData to RoleData and RoleMemberData
     * 2.   Migrates /ca_functionality/basic_functions and /ca_functionality/basic_functions/activate_ca
     *      to a single rule: /ca_functionality/activate_ca
     * 3.   Remove no longer used rules
     * 4.   Upgrades CAs and Certificate Profiles to go from having one approval profile for all approval types to having one for each
     *
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase680() throws UpgradeFailedException {
        log.debug("migrateDatabase680: Upgrading roles, rules and role members.");
        // Get largest possible list of all access rules on this system
        final Set<String> allResourcesInUseOnThisInstallation = authorizationSystemSession.getAllResources(true).keySet();
        // Migrate one AdminGroupData at the time
        final AccessRulesMigrator accessRulesMigrator = new AccessRulesMigrator(allResourcesInUseOnThisInstallation);
        final Collection<AdminGroupData> adminGroupDatas = legacyRoleManagementSession.getAllRoles();
        final boolean isInstalledOn660OrLater = !isLesserThan(getUpgradedFromVersion(), "6.6.0");
        for (final AdminGroupData adminGroupData : adminGroupDatas) {
            // Convert AdminGroupData and linked AccessRuleDatas to RoleData
            final String roleName = adminGroupData.getRoleName();
            final Collection<AccessRuleData> oldAccessRules = legacyRoleManagementSession.getAccessRules(adminGroupData.getPrimaryKey());
            HashMap<String, Boolean> newAccessRules = accessRulesMigrator.toNewAccessRules(oldAccessRules, roleName);
            //Migrate rules & rule states changed in 6.8.0.
            newAccessRules = migrate680Rules(newAccessRules, isInstalledOn660OrLater);
            Role role = new Role(null, roleName, newAccessRules);
            // Keep AdminGroupData.primaryKey as RoleData.roleId so HardTokenIssuerData.adminGroupId still works during upgrade
            // (and use direct DB access since the EJB API wont allow us to assign roleId)
            final int roleId = adminGroupData.getPrimaryKey().intValue();
            role.setRoleId(roleId);
            if (roleDataSession.getRole(roleId)!=null) {
                log.info("RoleData '" + role.getRoleName() + "' (" + role.getRoleId() + ") already exists. Will perform merge old role members into this role and overwrite configured access rules.");
            }
            role.normalizeAccessRules();
            role.minimizeAccessRules();
            roleDataSession.persistRole(role);
            // Convert the linked AccessUserAspectDatas to RoleMemberDatas
            List<AccessUserAspectData> accessUsers = legacyRoleManagementSession.getAccessUsers(adminGroupData.getPrimaryKey());
            // Each AccessUserAspectData belongs to one and only one role, so retrieving them this way may be considered safe.
            for (final AccessUserAspectData accessUserAspect : accessUsers) {
                final String tokenType = accessUserAspect.getTokenType();
                // Only the X509CertificateAuthenticationToken actually uses the CA Id, so leave it unset for the rest
                final int tokenIssuerId;
                if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) && accessUserAspect.getCaId()!=null) {
                    tokenIssuerId = accessUserAspect.getCaId().intValue();
                } else {
                    tokenIssuerId = RoleMember.NO_ISSUER;
                }
                final int tokenMatchKey = accessUserAspect.getMatchWith();
                int tokenMatchOperator = accessUserAspect.getMatchType();
                String tokenMatchValue = accessUserAspect.getMatchValue();
                String description = "";
                // Straighten out comparison operators that don't make sense, since previous versions of EJBCA might have allowed such configuration
                if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType)) {
                    if (tokenMatchKey == X500PrincipalAccessMatchValue.NONE.getNumericValue() ||
                            tokenMatchOperator == AccessMatchType.TYPE_NONE.getNumericValue()) {
                        // This will never match anything, drop it
                        log.info("Admin in role '" + roleName + "' of type " + tokenType + " with match key " + tokenMatchKey +
                                " match operator " + tokenMatchOperator + " and match value '" + tokenMatchValue +
                                "' will be dropped since it will never grant any access.");
                        continue;
                    }
                    if (tokenMatchKey == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue()) {
                        final String serialNumberUppercase = StringUtils.defaultString(tokenMatchValue).toUpperCase(Locale.ROOT).replaceFirst("^0+", "");
                        if (!serialNumberUppercase.equals(tokenMatchValue)) {
                            log.info("Admin in role '" + roleName + "' of type " + tokenType + " has serial number match value '" + tokenMatchValue +
                                    "'. In 6.8.0 all serial numbers are converted to uppercase without leading zeros and match as case sensitive.");
                        } else if (log.isDebugEnabled() && tokenMatchOperator == AccessMatchType.TYPE_EQUALCASEINS.getNumericValue()) {
                            log.debug("Admin in role '" + roleName + "' of type " + tokenType + " has case insensitive serial number match value '" + tokenMatchValue +
                                    "'. In 6.8.0 all serial numbers are converted to uppercase and match as case sensitive.");
                        }
                        tokenMatchOperator = AccessMatchType.TYPE_EQUALCASE.getNumericValue();
                        tokenMatchValue = serialNumberUppercase;
                        // If the certificate is present in the local database, we try to find a human readable description from the certificate
                        try {
                            final CAInfo caInfo = caSession.getCAInfoInternal(tokenIssuerId);
                            if (caInfo == null) {
                                log.info("Admin in role '" + roleName + "' of type " + tokenType + " with serial number match value '"
                                        + tokenMatchValue + "' is issued by a CA with ID " + tokenIssuerId
                                        + " that is unknown to this system. Migrating admin anyway.");
                            } else {
                                final String issuerDn = caInfo.getSubjectDN();
                                final Certificate certificate = certificateStoreSession.findCertificateByIssuerAndSerno(issuerDn,
                                        new BigInteger(tokenMatchValue, 16));
                                if (certificate != null) {
                                    final List<String> commonNames = CertTools.getPartsFromDN(CertTools.getSubjectDN(certificate), "CN");
                                    if (!commonNames.isEmpty()) {
                                        // Use the first found CN of the mapped certificate
                                        description = commonNames.get(0);
                                    }
                                } else {
                                    description = "external client certificate";
                                    // Since we made the database lookup, take the chance to inform about meaningless configuration
                                    if (WebConfiguration.getRequireAdminCertificateInDatabase()) {
                                        log.info("Admin in role '" + roleName + "' of type " + tokenType + " with serial number match value '"
                                                + tokenMatchValue + "' does match a local certificate even though this is required by the '"
                                                + WebConfiguration.CONFIG_REQCERTINDB + "' setting." + "Migrating admin anyway.");
                                    }
                                }
                            }
                        } catch (NumberFormatException e) {
                            log.warn("Admin in role '" + roleName + "' of type " + tokenType + " with serial number match value '" + tokenMatchValue
                                    + "' could not be interpreted as a hex value. Admin will not be migrated.");
                        }
                    }
                    if (tokenMatchOperator == AccessMatchType.TYPE_NOT_EQUALCASE.getNumericValue() ||
                            tokenMatchOperator == AccessMatchType.TYPE_NOT_EQUALCASEINS.getNumericValue()) {
                        log.warn("Admin in role '" + roleName + "' of type " + tokenType + " with match key=" + tokenMatchKey +
                                " match operator " + tokenMatchOperator + " and match value='"+tokenMatchValue +
                                "' is most likely misconfigured. This will grant role access to anything not matching the value!");
                    }
                } else if (CliAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) || "UsernameBasedAuthenticationToken".equals(tokenType)) {
                    if (tokenMatchOperator != AccessMatchType.TYPE_EQUALCASE.getNumericValue()) {
                        // The implementation always does case sensitive compare
                        if (log.isDebugEnabled()) {
                            log.debug("Admin in role '" + roleName + "' of type " + tokenType + " with match key " + CliUserAccessMatchValue.USERNAME.name() +
                                    " match operator " + tokenMatchOperator + " with and match value '" + tokenMatchValue +
                                    "'. Changing match operator type to defacto operator TYPE_EQUALCASE.");
                        }
                        tokenMatchOperator = AccessMatchType.TYPE_EQUALCASE.getNumericValue();
                    }
                } else {
                    // None of the other known tokens when writing this upgrade use any operator
                    tokenMatchOperator = AccessMatchType.TYPE_UNUSED.getNumericValue();
                }
                // Assign upgraded role members the same ID as the old AdminEndEntity.primaryKey so members are merged in case this runs several times (like in tests)
                // In 6.7.x we did not support OAuth provider authentication, so we set that to NO_PROVIDER
                roleMemberDataSession.persistRoleMember(new RoleMember(accessUserAspect.getPrimaryKey(), tokenType,
                        tokenIssuerId, RoleMember.NO_PROVIDER, tokenMatchKey, tokenMatchOperator, tokenMatchValue, roleId, description));
            }
        }
        // Note that this has to happen here and not in X509CA or CvcCA due to the fact that this step has to happen after approval profiles have
        // been created in previous upgrade steps.
        log.debug("migrateDatabase680: Converting Certificate Authorities from using one approval profile for all request types "
                + "to using one profile per request type.");
        try {
            for (int caId : caSession.getAllCaIds()) {
                CACommon ca = caSession.getCAForEdit(authenticationToken, caId);
                //If approvals map is null or empty, then this CA may be in an unupgraded state.
                if(ca.getApprovals() == null || ca.getApprovals().isEmpty()) {
                	Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
                    int approvalProfile = ca.getApprovalProfile();
                    if (approvalProfile != -1) {
                        for (int approvalSetting : ca.getApprovalSettings()) {
                            approvals.put(ApprovalRequestType.getFromIntegerValue(approvalSetting), approvalProfile);
                        }
                    }
                    ca.setApprovals(approvals);
                    caSession.editCA(authenticationToken, ca, true);
                }
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always allow token was denied access.", e);
        } catch (CADoesntExistsException e) {
            throw new IllegalStateException("CA doesn't exist in spite of just being retrieved", e);
        }
        // Note that this has to happen here and not in CertificateProfile due to the fact that this step has to happen after approval profiles have
        // been created in previous upgrade steps.
        log.debug("migrateDatabase680: Converting Certificate Profiles from using one approval profile for all request types "
                + "to using one profile per request type.");
        Map<Integer, CertificateProfile> certificateProfiles = certProfileSession.getAllCertificateProfiles();
        for (Integer profileId : certificateProfiles.keySet()) {
            CertificateProfile certificateProfile = certificateProfiles.get(profileId);
            String certificateProfileName = certProfileSession.getCertificateProfileName(profileId);
            Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
            int approvalProfile = certificateProfile.getApprovalProfileID();
            if (approvalProfile != -1) {
                for (int approvalSetting : certificateProfile.getApprovalSettings()) {
                    approvals.put(ApprovalRequestType.getFromIntegerValue(approvalSetting), approvalProfile);
                }
            }
            certificateProfile.setApprovals(approvals);
            try {
                certProfileSession.changeCertificateProfile(authenticationToken, certificateProfileName, certificateProfile);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Always allow token was denied access.", e);
            }

        }

        log.error("(This is not an error) Completed upgrade procedure to 6.8.0");
    }


    /**
     * Upgrade to EJBCA 6.10.1. 
     * Upgrading System configuration and certificate profiles with CT log label system
     */
    @SuppressWarnings("deprecation")
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase6101() throws UpgradeFailedException {
        log.debug("migrateDatabase6100: Upgrading CT logs");
        final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final Map<Integer, CertificateProfile> allCertProfiles = certProfileSession.getAllCertificateProfiles();
        final LinkedHashMap<Integer, CTLogInfo> allCtLogs = gc.getCTLogs();
        LinkedHashMap<Integer, CTLogInfo> updatedCtLogs = new LinkedHashMap<>();

        /* Determine new label for each log...
         * If Google log or previously set to mandatory (6.10), place log under label 'Mandatory'.
         * Gather remaining logs under the label 'Unlabeled'.
         */
        for (Map.Entry<Integer, CTLogInfo> ctLogInfo : allCtLogs.entrySet()) {
            CTLogInfo ctLog = ctLogInfo.getValue();
            if (ctLog.getUrl().contains("ct.googleapis.com") || ctLog.isMandatory()) {
                ctLog.setLabel("Mandatory");
            } else {
                ctLog.setLabel("Unlabeled");
            }
            updatedCtLogs.put(ctLog.getLogId(), ctLog);
        }

        // Save CT logs with new labels set
        gc.setCTLogs(updatedCtLogs);
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, gc);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always allow token was denied access.", e);
        }

        // Set CT labels corresponding to previously set CT logs in each cert profile
        for (Integer profileId : allCertProfiles.keySet()) {
            CertificateProfile certProfile = allCertProfiles.get(profileId);
            if (certProfile.isUseCertificateTransparencyInCerts() || certProfile.isUseCertificateTransparencyInOCSP() || certProfile.isUseCertificateTransparencyInPublishers()) {
                LinkedHashSet<String> labelsToSelect = new LinkedHashSet<>();
                final String certProfileName = certProfileSession.getCertificateProfileName(profileId);
                for (Integer ctLog : certProfile.getEnabledCTLogs()) {
                    if (updatedCtLogs.containsKey(ctLog)) {
                        labelsToSelect.add(updatedCtLogs.get(ctLog).getLabel());
                    }
                }
                certProfile.setEnabledCtLabels(labelsToSelect);
                
                // This means there were some mandatory- or Google logs selected before upgrade, i.e. it would be ideal to comply to Chrome CT policy
                if (labelsToSelect.size() > 1) {
                    certProfile.setNumberOfSctByValidity(true);
                    certProfile.setMaxNumberOfSctByValidity(true);
                    certProfile.setNumberOfSctByCustom(false);
                    certProfile.setMaxNumberOfSctByCustom(false);
                } else {
                    certProfile.setNumberOfSctByValidity(false);
                    certProfile.setMaxNumberOfSctByValidity(false);
                    certProfile.setNumberOfSctByCustom(true);
                    certProfile.setMaxNumberOfSctByCustom(true);
                    // Migrate old values...
                    // With the new label system, at least one log from each label will be written to, hence allowing a maximum / minimum
                    // lower than number of labels would lock out issuance.
                    if (certProfile.getCtMaxNonMandatoryScts() < labelsToSelect.size()) {
                        certProfile.setCtMaxScts(labelsToSelect.size());
                    } else {
                        certProfile.setCtMaxScts(certProfile.getCtMaxNonMandatoryScts());
                    }
                    if (certProfile.getCtMaxNonMandatorySctsOcsp() < labelsToSelect.size()) {
                        certProfile.setCtMaxSctsOcsp(labelsToSelect.size());
                    } else {
                        certProfile.setCtMaxSctsOcsp(certProfile.getCtMaxNonMandatorySctsOcsp());
                    }
                    if (certProfile.getCtMinNonMandatoryScts() < labelsToSelect.size()) {
                        certProfile.setCtMinScts(labelsToSelect.size());
                    } else {
                        certProfile.setCtMinScts(certProfile.getCtMinNonMandatoryScts());
                    }
                    if (certProfile.getCtMaxNonMandatorySctsOcsp() < labelsToSelect.size()) {
                        certProfile.setCtMaxSctsOcsp(labelsToSelect.size());
                    } else {
                        certProfile.setCtMaxSctsOcsp(certProfile.getCtMaxNonMandatorySctsOcsp());
                    }
                    if (certProfile.getCtMinNonMandatorySctsOcsp() < labelsToSelect.size()) {
                        certProfile.setCtMinSctsOcsp(labelsToSelect.size());
                    } else {
                        certProfile.setCtMinSctsOcsp(certProfile.getCtMinNonMandatorySctsOcsp());
                    }
                }
                
                try {
                    certProfileSession.changeCertificateProfile(authenticationToken, certProfileName, certProfile);
                } catch (AuthorizationDeniedException e) {
                    throw new IllegalStateException("Always allow token was denied access.", e);
                }
            }
        }
    }

    /**
     * Upgrade to EJBCA 6.11.0 
     * Provides all current Peer connector roles with the new set of rules, controlling access to protocols
     * on remote RA instances. All should be allowed by default to not cause any regressions. The rules are
     * only relevant for RA Peer connector roles.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase6110() throws UpgradeFailedException {
        log.debug("migrateDatabase6110: Adding new rules for protocol access on remote RA instances.");
        List<Role> allRoles = roleDataSession.getAllRoles();
        for (Role role : allRoles) {
            boolean isRaRequestRole = role.hasAccessToResource(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI);
            if (isRaRequestRole) {
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP), Role.STATE_ALLOW);
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_EST), Role.STATE_ALLOW);
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_WS), Role.STATE_ALLOW);
                roleDataSession.persistRole(role);
            }
        }
        
        log.debug("migrateDatabase6110: Checking if external scripts should remain enabled.");
        boolean enableScripts = false;
        final Map<Integer, BasePublisher> publishers = publisherSession.getAllPublishersInternal();
        for (final BasePublisher publisher : publishers.values()) {
            if (log.isDebugEnabled()) {
                log.debug("Checking publisher: " + publisher.getName());
            }
            if (GeneralPurposeCustomPublisher.class.getName().equals(publisher.getRawData().get(CustomPublisherContainer.CLASSPATH))) {
                if (log.isDebugEnabled()) {
                    log.debug("Found General Purpose Custom Publisher: " + publisher.getName());
                }
                enableScripts = true;
                break;
            }
        }
        if (enableScripts) {
            log.info("External scripts will remain enabled, since there's at least one General Purpose Custom Publisher.");
            final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            gc.setEnableExternalScripts(true);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, gc);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Always allow token was denied access.", e);
            }
        } else {
            log.info("External scripts will be disabled, since there are no General Purpose Custom Publishers. The setting can be changed under the 'System Configuration' page.");
        }
    }
    
    
    /**
     * Upgrades to EJBCA 6.12.0
     * @throws InternalKeyBindingNameInUseException 
     * 
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase6120() {
        log.debug("migrateDatabase6120: Importing OCSP extensions from ocsp.properties file and UnidFnr trust dir (if available)");
        importOcspExtensions();
        importUnidFnrTrustDir();
    }
    
    /**
     * Upgrade to EJBCA 6.14.0 
     * Provides all current Peer connector roles with the new rules, controlling access to SCEP (same procedure as 
     * migrateDatabase6110) on remote RA instances. Should be allowed by default to not cause any regressions. 
     * This rules is only relevant for RA Peer connector roles.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase6140() throws UpgradeFailedException {
        log.debug("migrateDatabase6140: Adding new rule for SCEP protocol access on remote RA instances.");
        List<Role> allRoles = roleDataSession.getAllRoles();
        for (Role role : allRoles) {
            boolean isRaRequestRole = role.hasAccessToResource(AccessRulesConstants.REGULAR_PEERCONNECTOR_INVOKEAPI);
            if (isRaRequestRole) {
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_ACME), Role.STATE_ALLOW);
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_REST), Role.STATE_ALLOW);
                role.getAccessRules().put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_PEERPROTOCOL_SCEP), Role.STATE_ALLOW);
                roleDataSession.persistRole(role);
            }
        }
    }
    
    
    /**
     * Upgrade to EJBCA 6.15.0 
     * 
     * All the CCE will get a new required flag with the default value set to true.
     *  
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase6150() throws UpgradeFailedException {
        log.debug("migrateDatabase6150: Adding new field (required) for custom certificate extensions.");
        
        AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = (AvailableCustomCertificateExtensionsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
        
        for (CertificateExtension customCertificateExtension : availableCustomCertExtensionsConfig.getAllAvailableCustomCertificateExtensions()) {
                customCertificateExtension.setRequiredFlag(true);
                try {
                    globalConfigurationSession.saveConfiguration(authenticationToken, availableCustomCertExtensionsConfig);
                } catch (AuthorizationDeniedException e) {
                    log.error("Authorization error while saving the updated configuration!", e);
                }
        }
    }

    /**
     * From EJBCA 6.12.0, all extensions defined in ocsp.properties are selected for each key binding instead. Since this
     * setting was global previously, it should be fair to add each extension to every OCSP key binding.
     */
    private void importOcspExtensions() {
        @SuppressWarnings("deprecation")
        final List<String> ocspExtensionOids = OcspConfiguration.getExtensionOids();
        if (ocspExtensionOids.isEmpty()) {
            log.debug("No OCSP extensions for import were found in ocsp.properties");
            return;
        }
        final List<Integer> ocspKbIds = internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS);
        for (Integer ocspKbId : ocspKbIds) {
            InternalKeyBinding ikbToEdit = internalKeyBindingDataSession.getInternalKeyBindingForEdit(ocspKbId);
            List<String> currentExtensions = ikbToEdit.getOcspExtensions();
            for (String extension : ocspExtensionOids) {
                if (!currentExtensions.contains(extension.replaceAll("\\*", ""))) {
                    currentExtensions.add(extension.replaceAll("\\*", ""));
                }
            }
            ikbToEdit.setOcspExtensions(currentExtensions);
            try {
                internalKeyBindingDataSession.mergeInternalKeyBinding(ikbToEdit);
            } catch (InternalKeyBindingNameInUseException e) {
                log.info("Could not update internal key binding: " + ikbToEdit.getName() + ". IKB is in use. ");
            }
        }
    }
    
    private void importUnidFnrTrustDir() {
        List<X509Certificate> trustedCerts = new ArrayList<>();
        Certificate cacert = null;
        boolean isUnidFnrEnabled = OcspConfiguration.isUnidEnabled();
        @SuppressWarnings("deprecation")
        String trustDir = OcspConfiguration.getUnidTrustDir();
        @SuppressWarnings("deprecation")
        String cacertfile = OcspConfiguration.getUnidCaCert();
        if (StringUtils.isEmpty(trustDir)) {
            // This installation is probably not using UnidFnr at all.
            log.debug("No UnidFnr Trust directory found. Skipping import (expected for most installations).");
            if (isUnidFnrEnabled) {
                log.error("No UnidFnr Trust directory found. Cannot procede import");
            }
            return;
        }
        
        // Read all files from trustDir, expect that they are PEM formatted certificates.
        CryptoProviderTools.installBCProviderIfNotAvailable();
        File dir = new File(trustDir);
        try {
            if (dir == null || dir.isDirectory() == false) {
                log.error("Could not read UnidFnr Trust Directory: " + dir.getCanonicalPath()+ " is not a directory.\nImport interrupted");
                return;                
            }
            File files[] = dir.listFiles();
            if (files == null || files.length == 0) {
                log.info("No files found in UnidFnr Trust directory: " + dir.getCanonicalPath() + ". Skipping import");
                return;
            }
            for (int i=0; i < files.length; i++) {
                final String fileName = files[i].getCanonicalPath();
                // Read the file, don't stop completely if one file has errors in it.
                try {
                    final byte bytesFromFile[] = FileTools.readFiletoBuffer(fileName);
                    byte[] bytes;
                    try {
                        bytes = FileTools.getBytesFromPEM(bytesFromFile, CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
                    } catch (Exception e) {
                        bytes = bytesFromFile; // assume binary data (.der).
                    }
                    final X509Certificate  cert = CertTools.getCertfromByteArray(bytes, X509Certificate.class);
                    trustedCerts.add(cert);
                } catch (CertificateException | IOException e) {
                    log.error("error reading '" + fileName + "' from trustDir: " + e.getMessage(), e);
                }
            }
        } catch (IOException e) {
            String errMsg = "Error reading files from trustDir: " + e.getMessage();
            log.error(errMsg, e);
            // Since the file exists but we can't read it. We should stop here and warn the user
            throw new IllegalStateException(errMsg);
        }
        // Read the CA Certificate file
        if (StringUtils.isEmpty(cacertfile)) {
            // Since this MUST be set if UnidFnr Extension is used, we should skip import if not found
            log.debug("No UnidFnr CA Cert directory found. Skipping import");
            if (isUnidFnrEnabled) {
                log.error("No UnidFnr CA Cert directory found. Cannot procede import");
            }
            return;
        }
        try {
            byte[] bytes = FileTools.getBytesFromPEM(FileTools
                    .readFiletoBuffer(cacertfile),
                    CertTools.BEGIN_CERTIFICATE, CertTools.END_CERTIFICATE);
            cacert = CertTools.getCertfromByteArray(bytes, Certificate.class);
        } catch (Exception e) {
            String errMsg = "Error reading CA Certificate from UnidFnr cacertfile";
            log.error(errMsg, e);
            // Since the file exists but we can't read it. We should stop here and warn the user
            throw new IllegalStateException(errMsg);
        }
        
        if (!CertTools.isCA(cacert)) {
            log.error(cacertfile + " does not point to a CA Certificate");
            return;
        }
        final String subjectdn = CertTools.getSubjectDN(cacert);
        
        final int caid = CertTools.stringToBCDNString(subjectdn).hashCode();
        try {
            caSession.verifyExistenceOfCA(caid);
        } catch (CADoesntExistsException e) {
            log.info("Could not add CA to OCSP Key Binding trusted certificates. " + subjectdn + " is not known by EJBCA.");
            return;
        }
        // Add all found certificate serial numbers to the IKB trust entries
        final List<Integer> ocspKbIds = internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS);
        for (Integer ocspKbId : ocspKbIds) {
            InternalKeyBinding ikbToEdit = internalKeyBindingDataSession.getInternalKeyBindingForEdit(ocspKbId);
            List<InternalKeyBindingTrustEntry> currentTrustEntries = ikbToEdit.getTrustedCertificateReferences();
            
            for (X509Certificate trustedCert : trustedCerts) {
                final String subjectDn = trustedCert.getSubjectDN().getName();
                final DNFieldExtractor dnFieldExtractor = new DNFieldExtractor(subjectDn, DNFieldExtractor.TYPE_SUBJECTDN);
                final String commonName = dnFieldExtractor.getFieldString(DNFieldExtractor.CN);
                currentTrustEntries.add(new InternalKeyBindingTrustEntry(caid, trustedCert.getSerialNumber(), commonName));
            }
            ikbToEdit.setTrustedCertificateReferences(currentTrustEntries);
            try {
                internalKeyBindingDataSession.mergeInternalKeyBinding(ikbToEdit);
            } catch (InternalKeyBindingNameInUseException e) {
                // Should not happen when merging
                log.info("Could not edit key binding: " + ikbToEdit.getName() + ". Name already in use");
            }
        }
    }
    
    private boolean postMigrateDatabase720() {
        log.info("Starting post upgrade to 7.2.0");
        setCustomCertificateValidityWithSecondsGranularity(true);
        log.info("Post upgrade to 7.2.0 complete.");
        return true;  
    }
    
    private boolean postMigrateDatabase740() {
        log.info("Starting post upgrade to 7.4.0");
        try {
            removeUnidFnrConfigurationFromCmp();

            // Counting the number of non normal CRLData rows
            final Query query = entityManager.createQuery("SELECT count(*) FROM CRLData WHERE crlPartitionIndex IS NULL OR crlPartitionIndex = 0 ");
            final long countOfRowsToBeNormalized = (long) query.getSingleResult();            
            
            final long startDataNormalization = System.currentTimeMillis();
            
            // Check whether it is an MSSQL database. If yes, don't normalize in chunks
            final String dbType = DatabaseConfiguration.getDatabaseName();
            if (MSSQL.equals(dbType)) {
                upgradeSession.fixPartitionedCrls(0, true);
            } else {
                // Normalization for non-MSSQL databases is done in chunks in case number of rows are huge in CRLData table.
                // This is to avoid the error "Got error 90 "Message too long" during COMMIT" in Galera clusters
                // See ECA-10712 for more info.
                for (int i = 0; i < countOfRowsToBeNormalized; i += PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE) {
                    upgradeSession.fixPartitionedCrls(PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE, false);
                    
                }
                // Do fix the remaining if any
                final Query normalizeData = entityManager.createQuery(
                        "UPDATE CRLData a SET a.crlPartitionIndex = -1 WHERE a.crlPartitionIndex IS NULL OR a.crlPartitionIndex=0");
                log.debug("Executing SQL query: " + normalizeData);
                normalizeData.executeUpdate();
                log.info("Successfully normalized " + countOfRowsToBeNormalized + " rows in CRLData. Completed in "
                        + (System.currentTimeMillis() - startDataNormalization) + " ms.");
            }
            
            fixPartitionedCrlIndexes();
        } catch (AuthorizationDeniedException | UpgradeFailedException e) {
            log.error(e);
            return false;
        }
        log.info("Post upgrade to 7.4.0 complete.");

        return true;  
    }

    @SuppressWarnings("deprecation")
    private boolean postMigrateDatabase7110() {
        log.info("Starting post upgrade to 7.11.0");
        try {
            // CMP
            log.debug("Removing CMP vendor names that have been converted to the new ID format");
            final CmpConfiguration cmpConfiguration =
                    (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            final LinkedHashMap<Object, Object> cmpRawData = cmpConfiguration.getRawData();
            for (final String cmpAlias : cmpConfiguration.getAliasList()) {
                cmpRawData.remove(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCA);
            }
            globalConfigurationSession.saveConfiguration(authenticationToken, cmpConfiguration);
            // EST
            log.debug("Removing EST vendor names that have been converted to the new ID format");
            final EstConfiguration estConfiguration =
                    (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
            final LinkedHashMap<Object, Object> estRawData = estConfiguration.getRawData();
            for (final String estAlias : estConfiguration.getAliasList()) {
                estRawData.remove(estAlias + "." + EstConfiguration.CONFIG_VENDORCA);
            }
            globalConfigurationSession.saveConfiguration(authenticationToken, estConfiguration);
        } catch (Exception e) {
            log.error(e);
            return false;
        }
        log.info("Post upgrade to 7.11.0 complete.");
        return true;
    }
    
    private boolean postMigrateDatabase6101() {
        log.info("Starting post upgrade to 6.10.1.");
        final Map<Integer, CertificateProfile> allCertProfiles = certProfileSession.getAllCertificateProfiles();

        for (Integer profileId : allCertProfiles.keySet()) {
            CertificateProfile certProfile = allCertProfiles.get(profileId);
            final String certProfileName = certProfileSession.getCertificateProfileName(profileId);
            certProfile.removeLegacyCtData();
            try {
                certProfileSession.changeCertificateProfile(authenticationToken, certProfileName, certProfile);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Always allow token was denied access.", e);
            }
        }
        log.info("Post upgrade to 6.10.1 complete.");
        return true;
    }


    @SuppressWarnings("deprecation")
    private boolean postMigrateDatabase680() {
        log.info("Starting post upgrade to 6.8.0.");
        // Verify that there are no TYPE_NOT_EQUALCASE* still in use
        log.info("Verifying that there are no TYPE_NOT_EQUALCASE or TYPE_NOT_EQUALCASEINS token match operators still in use.");
        boolean hasNotEquals = false;
        for (final Role role : roleSession.getAuthorizedRoles(authenticationToken)) {
            for (final RoleMember roleMember : roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId())) {
                final int tokenMatchOperator = roleMember.getTokenMatchOperator();
                if (AccessMatchType.TYPE_NOT_EQUALCASE.getNumericValue()==tokenMatchOperator ||
                        AccessMatchType.TYPE_NOT_EQUALCASEINS.getNumericValue()==tokenMatchOperator) {
                    log.error("Role '" + role.getRoleNameFull() + "' has a member with a 'not equals' match operator. Post-upgrade cannot complete until this is corrected.");
                    hasNotEquals = true;
                    break;
                }
            }
        }
        if (hasNotEquals) {
            return false;
        }
        // Change to use union role access rules instead of enum priority matching
        accessTreeUpdateSession.setNewAuthorizationPatternMarker();
        log.info("Admins belonging to multiple roles will now be granted the combined access when cache expires.");
        // Empty the legacy AdminEntityData, AdmingGroupData and AccessRulesData tables.
        if (EjbcaConfiguration.getIsInProductionMode()) {
            log.info("Cleaning up legacy roles and rules.");
            legacyRoleManagementSession.deleteAllRoles(authenticationToken);
        } else {
            log.warn("This EJBCA installation is not running in production mode, so the tables AdminEntityData, AdmingGroupData and AccessRulesData will not be emptied.");
        }
        log.info("Post upgrade to 6.8.0 complete.");
        return true;
    }

    /**
     * Since EJBCA 6.8.0, some rules are either removed or have a changed scope.
     * If Role had access to /ca_functionality/basic_functions or /ca_functionality/basic_functions/activate_ca,
     * grant access to new rule /ca_functionality/activate_ca
     *
     * If upgrading from 6.6.0 or later, grant access to /ca_functionality/view_certificate for roles with access
     * to ra_functionality/view_end_entity
     * @param newAccessRules HashMap of access rules to migrate
     * @param isInstalledOn660OrLater if upgrading from 6.6.0 or later
     * @return HashMap with migrated rule states
     */
    private HashMap<String, Boolean> migrate680Rules(HashMap<String, Boolean> newAccessRules, boolean isInstalledOn660OrLater) {
        Boolean isAllowedActivateCa = AccessRulesHelper.hasAccessToResource(newAccessRules, REGULAR_ACTIVATECA_OLD);
        Boolean isAllowedViewEndEntity = AccessRulesHelper.hasAccessToResource(newAccessRules, AccessRulesConstants.REGULAR_VIEWENDENTITY);
        if(isAllowedActivateCa) {
            newAccessRules.put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_ACTIVATECA), Role.STATE_ALLOW);
        } else {
            newAccessRules.put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_ACTIVATECA), Role.STATE_DENY);
        }
        //Remove deprecated rules
        newAccessRules.remove(AccessRulesHelper.normalizeResource(REGULAR_CABASICFUNCTIONS_OLD));
        newAccessRules.remove(AccessRulesHelper.normalizeResource(ROLE_PUBLICWEBUSER));
        newAccessRules.remove(AccessRulesHelper.normalizeResource(REGULAR_ACTIVATECA_OLD));
        if(isInstalledOn660OrLater && isAllowedViewEndEntity) {
            newAccessRules.put(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_VIEWCERTIFICATE), Role.STATE_ALLOW);
        }
        return newAccessRules;
    }

    /** Add the previously global configuration configured approval notification */
    @SuppressWarnings("deprecation")
    private void addApprovalNotification(final AccumulativeApprovalProfile newProfile) {
        final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        if (gc.getUseApprovalNotifications()) {
            final String baseUrl = gc.getBaseUrlFromConfig();
            final String defaultSubject = "[AR-${approvalRequest.ID}-${approvalRequest.STEP_ID}-${approvalRequest.PARTITION_ID}] " +
                    "Approval Request to ${approvalRequest.TYPE} is now in state ${approvalRequest.WORKFLOWSTATE}";
            final String defaultBody = "Approval Request to ${approvalRequest.TYPE} from ${approvalRequest.REQUESTOR} is now in state ${approvalRequest.WORKFLOWSTATE}.\n" +
                    "\n" +
                    "Direct link to the request: " + baseUrl + "ra/managerequest.xhtml?aid=${approvalRequest.ID}";
            final ApprovalPartition approvalPartition = newProfile.getFirstStep().getPartitions().values().iterator().next();
            newProfile.addNotificationProperties(approvalPartition, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), defaultSubject, defaultBody);
        }
    }

    /**
     * The configuration files <code>certstore.properties</code> and <code>crlstore.properties</code> are removed as of EJBCA 7.2.
     * <p>This method adjusts the configuration as follows:
     * <ul>
     *     <li>If upgrading from EJBCA 6.10 or older, the servlets will always become enabled in modular protocols configuration, regardless of whether it was available in the previous deployment or not.</li>
     *     <li>If upgrading from EJBCA 6.11 or later and the servlet was unavailable in the previous deployment it is disabled in modular protocols configuration.</li>
     *     <li>If upgrading from EJBCA 6.11 or later and the servlet was available in the previous deployment, the existing setting in modular protocols configuration will remain.</lI>
     * <ul>
     */
    @Override
    public void upgradeCrlStoreAndCertStoreConfiguration720() {
        log.debug("Starting adjustment of CRL Store and Cert Store settings in modular protocols configuration...");
        final AvailableProtocolsConfiguration protocolsConfiguration = (AvailableProtocolsConfiguration) globalConfigurationSession
                .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
        log.debug("Retrieved modular protocols configuration object: " + protocolsConfiguration.getRawData());
        if (isLesserThan(getLastUpgradedToVersion(), "6.11.0")) {
            // If upgrading from EJBCA 6.10 or older, there is no way of determining whether the servlet was available in the
            // previous deployment or not. If we do nothing, the servlet will be enabled by default. This is probably the best
            // choice, since we won't magically break stuff.
            log.info("Upgrading from EJBCA " + getLastUpgradedToVersion() + " without modular protocols configuration implemented. Assuming servlets were "
                    + "available in the previous deployment. Please disable them manually in 'System Configuration -> Protocol Configuration' if desired.");
        } else {
            // Servlet was unavailable in the previous deployment if there is no configuration value set for it
            if (protocolsConfiguration.getRawData().get(AvailableProtocols.CRL_STORE.getName()) == null) {
                log.info("CRL Store was not available in the previous deployment, it will be disabled in modular protocols configuration.");
                protocolsConfiguration.setProtocolStatus(AvailableProtocols.CRL_STORE.getName(), false);
            }
            if (protocolsConfiguration.getRawData().get(AvailableProtocols.CERT_STORE.getName()) == null) {
                log.info("Cert Store was not available in the previous deployment, it will be disabled in modular protocols configuration.");
                protocolsConfiguration.setProtocolStatus(AvailableProtocols.CERT_STORE.getName(), false);
            }
        }

        log.debug("Adjustment of CRL Store and Cert Store settings in modular protocols configuration finished.");
    }

    @Override
    public void migrateDatabase730() {
        migrateOcspKeyBindings730();
        removeStaleAccessRules730();
    }

    private void removeStaleAccessRules730() {
        try {
            final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (!globalConfiguration.getEnableKeyRecovery()) {
                log.info("Key recovery is disabled. Checking if there are any stale access rules to remove...");
                for (final Role role : roleSession.getAuthorizedRoles(authenticationToken)) {
                    if (role.getAccessRules().containsKey(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY))) {
                        role.getAccessRules().remove(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY));
                        roleSession.persistRole(authenticationToken, role);
                        log.info("Removed access rule " + AccessRulesConstants.REGULAR_KEYRECOVERY + " from role " + role.getRoleName());
                    }
                }
            }
        } catch (AuthorizationDeniedException e) {
            log.error("Not all stale access rules may have been removed, authorisation to one or more resources was denied.", e);
        } catch (RoleExistsException e) {
            log.error("Not all stale access rules may have been removed, failed to overwrite existing role.", e);
        }
    }

    private void migrateOcspKeyBindings730() {
        try {
            log.info("Migrating settings for archive cutoff (RFC6960) to internal key bindings.");
            if (ConfigurationHolder.getString("ocsp.expiredcert.retentionperiod") == null) {
                log.warn("The property ocsp.expiredcert.retentionperiod was not set, disabling archive cutoff.");
                return;
            } else {
                log.debug("The property ocsp.expiredcert.retentionperiod has the value '" + ConfigurationHolder.getString("ocsp.expiredcert.retentionperiod") + "'.");
            }
            final String configuredValue = ConfigurationHolder.getString("ocsp.expiredcert.retentionperiod");
            final long retentionPeriodInSeconds = Long.parseLong(StringUtils.trim(configuredValue));
            if (retentionPeriodInSeconds == -1L) {
                // The archive cutoff extension is disabled
                log.info("The archive cutoff extension is disabled on this EJBCA instance. Nothing to do.");
                return;
            }
            final List<Integer> ocspKeyBindingIds = internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS);
            log.debug("Fetched " + ocspKeyBindingIds.size() + " OCSP key bindings from the database.");
            for (final int ocspKeyBindingId : ocspKeyBindingIds) {
                final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingDataSession.getInternalKeyBinding(ocspKeyBindingId);
                final List<String> ocspExtensions = ocspKeyBinding.getOcspExtensions();
                if (ocspExtensions.contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
                    // The archive cutoff extension already exists
                    log.info("We already have an Archive Cutoff extension, not adding a new one.");
                } else {
                    ocspExtensions.add(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId());
                    ocspKeyBinding.setOcspExtensions(ocspExtensions);
                }
                ocspKeyBinding.setRetentionPeriod(SimpleTime.getInstance(retentionPeriodInSeconds * 1000L));
                internalKeyBindingDataSession.mergeInternalKeyBinding(ocspKeyBinding);
                log.info("Added id-pkix-ocsp-archive-cutoff with a retention period of " + retentionPeriodInSeconds + " seconds to OCSP key binding "
                        + ocspKeyBinding.getName() + " (" + ocspKeyBindingId + ").");
            }
            log.info("Successfully migrated OCSP key bindings.");
        } catch (NumberFormatException e) {
            log.fatal("The property 'ocsp.expiredcert.retentionperiod' does not contain a valid integer. Fix the problem and restart the application server.");
            throw e;
        } catch (InternalKeyBindingNameInUseException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Try to update the database to make it possible to use 'Partitioned CRLs' on existing installations using
     * default database indexes by modifying the <code>CRLData</code> table.
     *
     * <p>crlPartitionIndex values containing 0 or NULL are normalized to -1 and indexes are created over
     * <code>(issuerDN, crlPartitionIndex, deltaCRLIndicator, cRLNumber)</code> and
     * <code>(issuerDN, crlPartitionIndex, cRLNumber)</code>. See ECA-8680 for more details.
     *
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes.
     *
     * @return true if migration should be considered complete and the <code>lastPostUpgradedToVersion</code>
     * value in the database should be incremented.
     * @throws UpgradeFailedException if upgrade fails
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void fixPartitionedCrls(final int limit, final boolean isMSSQL) throws UpgradeFailedException {
        try {
            // Do the whole normalization at once in the case of MSSQL
            if (isMSSQL) {
                final long startDataNormalization = System.currentTimeMillis();
                final Query normalizeData = entityManager.createQuery(
                        "UPDATE CRLData a SET a.crlPartitionIndex=-1 WHERE a.crlPartitionIndex IS NULL OR a.crlPartitionIndex=0");
                log.debug("Executing SQL query: " + normalizeData);
                final int rowCount = normalizeData.executeUpdate();
                log.info("Successfully normalized " + rowCount + " rows in CRLData. Completed in "
                        + (System.currentTimeMillis() - startDataNormalization) + " ms.");
                // If not MSSQL normalize only a set amount at a time
            } else {
                final Query normalizeData = entityManager.createNativeQuery(
                        "UPDATE CRLData a SET a.crlPartitionIndex = -1 WHERE a.crlPartitionIndex IS NULL OR a.crlPartitionIndex=0  LIMIT :limit");
                normalizeData.setParameter("limit", limit);
                log.debug("Executing SQL query: " + normalizeData);
                normalizeData.executeUpdate();
            }

        } catch (RuntimeException e) {
            log.error("An error occurred when updating data in database table 'CRLData': " + e);
            log.error("You can update the data manually using the following SQL query and then run the post-upgrade again.");
            log.error("    UPDATE CRLData SET crlPartitionIndex=-1 WHERE crlPartitionIndex IS NULL OR crlPartitionIndex=0;");
            throw new UpgradeFailedException(e);
        }
    }

    private void fixPartitionedCrlIndexes() {
        final IndexUpgradeResult res3 = upgradeSession.upgradeIndex("crldata_idx3", "CRLData", "CREATE INDEX crldata_idx5 ON CRLData(cRLNumber, issuerDN, crlPartitionIndex)");
        final IndexUpgradeResult res4 = upgradeSession.upgradeIndex("crldata_idx4", "CRLData", "CREATE UNIQUE INDEX crldata_idx6 ON CRLData(issuerDN, crlPartitionIndex, deltaCRLIndicator, cRLNumber)");
        if (res3 != IndexUpgradeResult.OK_UPDATED || res4 != IndexUpgradeResult.OK_UPDATED) {
            if (res3 == IndexUpgradeResult.NO_EXISTNG_INDEX || res4 == IndexUpgradeResult.NO_EXISTNG_INDEX) {
                log.warn("Indexes for CRLs could not be dropped. Perhaps they did not exist?");
            }
            log.info("You can update the indexes manually by running the following SQL queries:");
            log.info("    DROP INDEX IF EXISTS crldata_idx3 ON CRLData;");
            log.info("    DROP INDEX IF EXISTS crldata_idx4 ON CRLData;");
            log.info("    CREATE INDEX IF NOT EXISTS crldata_idx5 ON CRLData(cRLNumber, issuerDN, crlPartitionIndex);");
            log.info("    CREATE UNIQUE INDEX IF NOT EXISTS crldata_idx6 ON CRLData(issuerDN, crlPartitionIndex, deltaCRLIndicator, cRLNumber);");
            log.info("These changes are only needed if you want to use 'Partitioned CRLs'. See ECA-8680.");
            log.info("If an index could not be created because duplicates were found you could remove them using something like:" + System.lineSeparator() +
                "    DELETE t1 FROM CRLData t1, CRLData t2 WHERE t1.fingerprint > t2.fingerprint AND t1.issuerDN = t2.issuerDN " + System.lineSeparator() +
                    "AND t1.deltaCRLIndicator = t2.deltaCRLIndicator AND t1.cRLNumber = t2.cRLNumber AND t1.crlPartitionIndex = t2.crlPartitionIndex;");
            // Consider the post-upgrade to be complete, even if this fails. The user can manually add indexes later.
        }
    }

    /**
     * Replaces a database index. Called by {@link #fixPartitionedCrlIndexes}.
     * Runs in a new transaction because the queries will fail if the index does not exist.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public IndexUpgradeResult upgradeIndex(final String oldIndexName, final String tableName, final String createIndexQuery) {
        try {
            final long startReindex = System.currentTimeMillis();
            // Unfortunately, "IF EXISTS" and "IF NOT EXISTS" are not supported in index
            // operations in mariadb-connector (tested with version 2.7.3)
            final Query dropCrlDataIndex = entityManager.createNativeQuery("DROP INDEX " + oldIndexName + " ON " + tableName);
            final Query createCrlDataIndex = entityManager.createNativeQuery(createIndexQuery);
            try {
                log.debug("Executing SQL query: " + dropCrlDataIndex);
                dropCrlDataIndex.executeUpdate();
            } catch (RuntimeException e) {
                log.warn("Index '" + oldIndexName + "' could not be dropped.");
                log.debug("Error stack trace for index removal: " + e, e);
                // Since the old indexes don't exist, we assume the user does not want the new indexes either
                return IndexUpgradeResult.NO_EXISTNG_INDEX;
            }
            log.debug("Executing SQL query: " + createCrlDataIndex);
            createCrlDataIndex.executeUpdate();
            log.info("Successfully updated index '" + oldIndexName + "' for database table '" + tableName + "'. Completed in " + (System.currentTimeMillis() - startReindex) + " ms.");
            return IndexUpgradeResult.OK_UPDATED;
        } catch (RuntimeException e) {
            log.error("An error occurred when adjusting index '" + oldIndexName + "' for database table '" + tableName + "': " + e);
            if (log.isDebugEnabled()) {
                log.debug("Error stack trace for index creation", e);
            }
            return IndexUpgradeResult.ERROR;
        }
    }

    /**
     * Migrate the OCSP logging configuration in ocsp.properties to {@link GlobalOcspConfiguration}.
     * @throws UpgradeFailedException if the configuration could not be migrated
     */
    @Override
    public void migrateDatabase780() throws UpgradeFailedException {
        try {
            final GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration)
                    globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            if (globalOcspConfiguration.getRawData().get("isOcspTransactionLoggingEnabled") != null) {
                log.info("Skipping migration of OCSP logging settings from ocsp.properties to the database " +
                        "as it looks like data has been migrated already.");
                if (log.isDebugEnabled()) {
                    log.debug("Existing data found in the database: " + System.lineSeparator() + globalOcspConfiguration.getRawData());
                }
                return;
            }
            String value = ConfigurationHolder.getString("ocsp.audit-log");
            final boolean isOcspAuditLoggingEnabled = "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
            globalOcspConfiguration.setIsOcspAuditLoggingEnabled(isOcspAuditLoggingEnabled);
            log.info("Migrated ocsp.audit-log => " + isOcspAuditLoggingEnabled);

            value = ConfigurationHolder.getString("ocsp.log-date");
            globalOcspConfiguration.setOcspLoggingDateFormat(value);
            log.info("Migrated ocsp.log-date => " + value);

            // value = ConfigurationHolder.getString("ocsp.log-timezone")
            log.info("Ignoring ocsp.log-timezone, using the timezone in blah instead. This behaviour is not configurable.");

            value = ConfigurationHolder.getString("ocsp.audit-log-pattern");
            globalOcspConfiguration.setOcspAuditLogPattern(value);
            log.info("Migrated ocsp.audit-log-pattern => " + value);

            value = ConfigurationHolder.getString("ocsp.audit-log-order");
            value = value.replace("\\\"", "\"");
            globalOcspConfiguration.setOcspAuditLogValues(value);
            log.info("Migrated ocsp.audit-log-order => " + value);

            value = ConfigurationHolder.getString("ocsp.trx-log");
            final boolean isOcspTransactionLoggingEnabled = "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
            globalOcspConfiguration.setIsOcspTransactionLoggingEnabled(isOcspTransactionLoggingEnabled);
            log.info("Migrated ocsp.trx-log => " + value);

            value = ConfigurationHolder.getString("ocsp.trx-log-pattern");
            globalOcspConfiguration.setOcspTransactionLogPattern(value);
            log.info("Migrated ocsp.trx-log-pattern => " + value);

            value = ConfigurationHolder.getString("ocsp.trx-log-order");
            value = value.replace("\\\"", "\"");
            globalOcspConfiguration.setOcspTransactionLogValues(value);
            log.info("Migrated ocsp.trx-log-order => " + value);

            // Avoid inserting faulty values into the database, as this will prevent EJBCA from starting.
            try {
                final TransactionLogger transactionLogger = new TransactionLogger(
                        1,
                        GuidHolder.INSTANCE.getGlobalUid(),
                        "127.0.0.1",
                        globalOcspConfiguration);
                transactionLogger.paramPut(PatternLogger.STATUS, "(Ocsp-Request-Status -> Int)");
                transactionLogger.paramPut(TransactionLogger.REQ_NAME, "(Requestor-Name -> String)");
                transactionLogger.paramPut(TransactionLogger.REQ_NAME_RAW, "(Requestor-Name-Raw -> String)");
                transactionLogger.paramPut(TransactionLogger.SIGN_ISSUER_NAME_DN, "(Ocsp-Signer-Issuer-Dn -> String)");
                transactionLogger.paramPut(TransactionLogger.SIGN_SUBJECT_NAME, "(Ocsp-Signer-Subject-Name -> String)");
                transactionLogger.paramPut(TransactionLogger.SIGN_SERIAL_NO, "(Ocsp-Signer-Serial-No -> Int)");
                transactionLogger.paramPut(TransactionLogger.NUM_CERT_ID, "(Cert-ID -> Int");
                transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN, "(Issuer-Name-Dn -> String");
                transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN_RAW, "(Issuer-Name-Dn-Raw) -> String");
                transactionLogger.paramPut(PatternLogger.ISSUER_NAME_HASH, "(Issuer-Name-Hash -> String)");
                transactionLogger.paramPut(PatternLogger.ISSUER_KEY, "(Issuer-Key -> String)");
                transactionLogger.paramPut(TransactionLogger.DIGEST_ALGOR, "(Digest-Algorithm -> String)");
                transactionLogger.paramPut(PatternLogger.SERIAL_NOHEX, "(Certificate-Serial-No -> String)");
                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, "(Cert-Status -> Int)");
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, "(Process-Time -> Int)");
                transactionLogger.paramPut(TransactionLogger.CERT_PROFILE_ID, "(Cert-Profile-Id -> Int)");
                transactionLogger.paramPut(TransactionLogger.FORWARDED_FOR, "(X-Forwarded-For -> String)");
                transactionLogger.paramPut(TransactionLogger.REV_REASON, "(Revocation-Reason -> String)");
                transactionLogger.interpolate();

                final AuditLogger auditLogger = new AuditLogger(
                        "(Ocsp-Request -> Bytes)",
                        2,
                        GuidHolder.INSTANCE.getGlobalUid(),
                        "127.0.0.1",
                        globalOcspConfiguration);
                auditLogger.paramPut(AuditLogger.OCSPRESPONSE, "(OCSP-Response -> Bytes)");
                auditLogger.paramPut(PatternLogger.STATUS, "(Ocsp-Request-Status -> Int)");
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, "(Process-Time -> Int)");
                auditLogger.interpolate();

                new SimpleDateFormat(globalOcspConfiguration.getOcspLoggingDateFormat()).toString();
            } catch (Exception e) {
                log.error("Failed to validate the current OCSP logging configuration. The error is: " + e.getMessage()
                        + ". Adjust the configuration in ocsp.properties and redeploy the application. If you don't " +
                        "know what to do, simply delete ocsp.properties to deploy the application with the default values.");
                throw new UpgradeFailedException(e);
            }

            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
            log.info("Migration of the OCSp audit log and OCSP transaction log settings from ocsp.properties completed!");
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage());
            throw new UpgradeFailedException(e);
        }
    }

    /**
     * Update GoogleCtPolicy.
     *
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes.
     *
     * @throws UpgradeFailedException if upgrade fails
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase781() throws UpgradeFailedException {
        final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        GoogleCtPolicy ctPolicy = globalConfig.getGoogleCtPolicy();
        ctPolicy.setBreakpoints(ctPolicy.getBreakpoints());
        for (int i = 0; i < 4; i++) {
            ctPolicy.getBreakpoints().get(i).setMinSct(ctPolicy.getMinScts()[i]);
        }
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, globalConfig);
        } catch (AuthorizationDeniedException e) {
            log.error("An error occurred when updating GoogleCtPolicy: " + e);
            throw new UpgradeFailedException(e);
        }
    }

    static class EeProfileUpdgaderFor781 {
        private static final int OLDFIELDBOUNDRARY  = 10000; // 7.8.0 and earlier

        // Private Constants in EndEntityProfile in version 7.8.1
        private static final int FIELDBOUNDRARY  = 1000000; // Changed in 7.8.1
        private static final int NUMBERBOUNDRARY = 100; // Field identifier number boundary
        private static final int FIELDORDERINGBASE = FIELDBOUNDRARY / NUMBERBOUNDRARY; //Introduced in 7.8.1 as SDN, SAN, SDA and SSH Field ordering base
        private static final String SUBJECTDNFIELDORDER       = "SUBJECTDNFIELDORDER";
        private static final String SUBJECTALTNAMEFIELDORDER  = "SUBJECTALTNAMEFIELDORDER";
        private static final String SUBJECTDIRATTRFIELDORDER  = "SUBJECTDIRATTRFIELDORDER";
        private static final String SSH_FIELD_ORDER = "SSH_FIELD_ORDER";

        private EeProfileUpdgaderFor781() {}

        static boolean shouldUpdate(EndEntityProfile eep) {
            LinkedHashMap<Object, Object> data = eep.getRawData();
            // check if the EEP already upgraded by checking existence of the key 1000000, in older EEP, username was saved with key 10000
            return !data.keySet().contains(FIELDBOUNDRARY);
        }

        @SuppressWarnings("unchecked")
        static void update(EndEntityProfile eep) {
            LinkedHashMap<Object, Object> data = eep.getRawData();
            LinkedHashMap<Object, Object> upgradedData = new LinkedHashMap<>();
            ArrayList<Integer> upgradedSdnFieldOrder = new ArrayList<>();
            ArrayList<Integer> upgradedSanFieldOrder = new ArrayList<>();
            ArrayList<Integer> upgradedSdaFieldOrder = new ArrayList<>();
            ArrayList<Integer> upgradedSshFieldOrder = new ArrayList<>();

            data.forEach((key, value) -> {
                if (key instanceof Integer) {
                    final Integer oldKey = (Integer) key;
                    final Integer fieldType = oldKey / OLDFIELDBOUNDRARY;
                    final Integer newKey = fieldType * FIELDBOUNDRARY + (oldKey % OLDFIELDBOUNDRARY);

                    upgradedData.put(newKey, value);
                } else if (SUBJECTDNFIELDORDER.contains(String.valueOf(key))) {
                    upgradedSdnFieldOrder.addAll(getFieldOrderWithUpgradedValues((List<Integer>)value));
                } else if (SUBJECTALTNAMEFIELDORDER.contains(String.valueOf(key))) {
                    upgradedSanFieldOrder.addAll(getFieldOrderWithUpgradedValues((List<Integer>)value));
                } else if (SUBJECTDIRATTRFIELDORDER.contains(String.valueOf(key))) {
                    upgradedSdaFieldOrder.addAll(getFieldOrderWithUpgradedValues((List<Integer>)value));
                } else if (SSH_FIELD_ORDER.contains(String.valueOf(key))) {
                    upgradedSshFieldOrder.addAll(getFieldOrderWithUpgradedValues((List<Integer>)value));
                } else {
                    upgradedData.put(key, value);
                }
            });
            data.clear();
            data.put(SUBJECTDNFIELDORDER, upgradedSdnFieldOrder);
            data.put(SUBJECTALTNAMEFIELDORDER, upgradedSanFieldOrder);
            data.put(SUBJECTDIRATTRFIELDORDER, upgradedSdaFieldOrder);
            data.put(SSH_FIELD_ORDER, upgradedSshFieldOrder);
            data.putAll(upgradedData);

        }

        private static List<Integer> getFieldOrderWithUpgradedValues(List<Integer> fieldOrder) {
            return fieldOrder.stream()
                .map(value -> {
                    final Integer fieldNumber = value / NUMBERBOUNDRARY;
                    final Integer index = value % NUMBERBOUNDRARY;
                    return FIELDORDERINGBASE * fieldNumber + index;
                }).collect(Collectors.toList());
        }
    }

    /**
     * Adds new access rules added in 7.10.0
     *
     * @throws UpgradeFailedException if upgrade fails
     */
    @Override
    public void migrateDatabase7100() throws UpgradeFailedException {
        final String ruleCreateCert = AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_CREATECERTIFICATE);
        final String ruleKeyRecovery = AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY);
        final String ruleUsePassword = AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_USEUSERNAME);
        final String ruleUseApprovalRequestId = AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_USEAPPROVALREQUESTID);
        try {
            log.debug("migrateDatabase7100: Checking if roles need added access rules added in 7.10.0");
            for (final Role role : roleSession.getAuthorizedRoles(authenticationToken)) {
                final LinkedHashMap<String, Boolean> access = role.getAccessRules();
                if (Boolean.TRUE.equals(access.get(ruleCreateCert)) || Boolean.TRUE.equals(access.get(ruleKeyRecovery))) {
                    // Users that can create or recover certs should still be able to do so.
                    log.info("Adding new access rules to '" + role.getRoleNameFull() + "'");
                    access.put(ruleUsePassword, true);
                    access.put(ruleUseApprovalRequestId, true);
                    AccessRulesHelper.minimizeAccessRules(access);
                    roleSession.persistRole(authenticationToken, role);
                }
            }
        } catch (AuthorizationDeniedException | RoleExistsException e) {
            log.error("An error occurred when updating roles for 7.10.0: " + e, e);
            throw new UpgradeFailedException(e);
        }
    }

    @Override
    public void migrateDatabase7110() throws UpgradeFailedException {
        log.debug("migrateDatabase7110: Converting vendor CAs previously stored using names to use IDs instead");
        final HashMap<Integer, String> caIdToNameMap = (HashMap<Integer, String>) caSession.getCAIdToNameMap();
        // CMP
        final CmpConfiguration cmpConfiguration =
                (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        for (final String cmpAlias : cmpConfiguration.getAliasList()) {
            log.debug("Converting vendor CA list for CMP alias: " + cmpAlias);
            @SuppressWarnings("deprecation")
            final String cmpVendorCaNameString = cmpConfiguration.getValue(cmpAlias + "." + CmpConfiguration.CONFIG_VENDORCA, cmpAlias);
            if (StringUtils.isEmpty(cmpVendorCaNameString)) {
                continue;
            }
            final String[] cmpVendorCaNames = cmpVendorCaNameString.split(";");
            final ArrayList<String> cmpVendorCaIds = new ArrayList<>();
            for (String cmpVendorName : cmpVendorCaNames) {
                boolean cmpVendorCaFound = false;
                for (final Integer caId : caIdToNameMap.keySet()) {
                    final String currentCmpVendorCaName = caIdToNameMap.get(caId);
                    if (StringUtils.equals(cmpVendorName.trim(), currentCmpVendorCaName.trim())) {
                        cmpVendorCaIds.add(caId.toString());
                        cmpVendorCaFound = true;
                        break;
                    }
                }
                if (!cmpVendorCaFound) {
                    log.debug("CMP vendor with name: " + cmpVendorName + " was not found, it will be removed");
                }
            }
            cmpConfiguration.setVendorCaIds(cmpAlias, StringUtils.join(cmpVendorCaIds, ";"));
        }
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, cmpConfiguration);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
        // EST
        EstConfiguration estConfiguration =
                (EstConfiguration) globalConfigurationSession.getCachedConfiguration(EstConfiguration.EST_CONFIGURATION_ID);
        for (final String estAlias : estConfiguration.getAliasList()) {
            log.debug("Converting vendor CA list for EST alias: " + estAlias);
            @SuppressWarnings("deprecation")
            final String estVendorCaNamesString = estConfiguration.getValue(estAlias + "." + EstConfiguration.CONFIG_VENDORCA, estAlias);
            if (StringUtils.isEmpty(estVendorCaNamesString)) {
                continue;
            }
            final String[] estVendorCaNames = estVendorCaNamesString.split(";");
            final ArrayList<String> estVendorCaIds = new ArrayList<>();
            for (String estVendorName : estVendorCaNames) {
                boolean estVendorCaFound = false;
                for (final Integer caId : caIdToNameMap.keySet()) {
                    final String currentEstVendorCaName = caIdToNameMap.get(caId);
                    if (StringUtils.equals(estVendorName.trim(), currentEstVendorCaName.trim())) {
                        estVendorCaIds.add(caId.toString());
                        estVendorCaFound = true;
                        break;
                    }
                }
                if (!estVendorCaFound) {
                    log.debug("EST vendor with name: " + estVendorName + " was not found, it will be removed");
                }
            }
            estConfiguration.setVendorCaIds(estAlias, StringUtils.join(estVendorCaIds, ";"));
        }
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, estConfiguration);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
    }

    @Override
    public void migrateDatabase800() throws UpgradeFailedException {
        log.debug(">migrateDatabase800");
        // New extended key usage ECA-11201
        final AvailableExtendedKeyUsagesConfiguration config =
                (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID);
        if (!config.isExtendedKeyUsageSupported("1.3.6.1.5.5.7.3.36")) {
            config.addExtKeyUsage("1.3.6.1.5.5.7.3.36", "EKU_DOCUMENT_SIGNING_RFC9336");
        }
        log.debug("Added RFC9336 Extended Key USage to availabe key usages list");
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, config);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
    }
    
    /**
     * Checks if the column cAId column exists in AdminGroupData
     *
     * @return true or false if the column exists or not
     */
    @Override
    public boolean checkColumnExists500() {
		// Try to find out if caID exists in AdminGroupData, which it did prior to EJBCA 5
        // If it does exist, a post-upgrade has to be done
		Connection connection;
        try {
            connection = JDBCUtil.getDBConnection();
        } catch (ServiceLocatorException e) {
            throw new IllegalStateException("Could not establish connection to database.", e);
        }
		boolean exists = false;
		try {
			final PreparedStatement stmt = connection.prepareStatement("select cAId from AdminGroupData where pk='0'");
			stmt.executeQuery();
			// If it did not throw an exception the column exists and we must run the post upgrade sql
			exists = true;
			log.info("cAId column exists in AdminGroupData");
		} catch (SQLException e) {
			// Column did not exist, it's good we are running a newer version
			log.info("cAId column does not exist in AdminGroupData");
			//log.debug(e.getMessage());
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				// do nothing
			}
		}
		return exists;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isLesserThan(final String first, final String second) {
        return StringTools.isLesserThan(first, second);
    }
}
