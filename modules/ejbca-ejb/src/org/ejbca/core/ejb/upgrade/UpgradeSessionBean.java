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
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.certificates.ca.CADoesntExistsException;
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
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalCaConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.cesecore.util.SimpleTime;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.GeneralPurposeCustomPublisher;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.util.JDBCUtil;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Resource;
import jakarta.ejb.AsyncResult;
import jakarta.ejb.Asynchronous;
import jakarta.ejb.EJB;
import jakarta.ejb.SessionContext;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

/**
 * The upgrade session bean is used to upgrade the database between EJBCA
 * releases.
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class UpgradeSessionBean implements UpgradeSessionLocal, UpgradeSessionRemote {

    private static final int PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE = 1000;
    private static final String MSSQL = "mssql";

    private final AppendingLogger log = new AppendingLogger(Logger.getLogger(UpgradeSessionBean.class));

    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("Internal upgrade");
    
    //Used to remove the configuration checker during post-upgrade to 8.3
    private static final String CONFIGURATION_CHECKER_CONFIGURATION_ID = "ISSUE_TRACKER";

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
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;
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
                setLastPostUpgradedToVersion("9.3.0");
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
        if (isLesserThan(oldVersion, "6.8.0")) {
            log.error(
                    "Upgrading from EJBCA prior to version 6.8.0 is forbidden. Read the EJBCA Upgrade Guide for more information.");
            return false;
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
        if (isLesserThan(oldVersion, "8.3.0")) {
            try {
                upgradeSession.migrateDatabase830();
            } catch (UpgradeFailedException e) {
                return false;
            }
        }        
        if (isLesserThan(oldVersion, "9.2.0")) {
            try {
                upgradeSession.migrateDatabase920();
            } catch (UpgradeFailedException e) {
                return false;
            }
        }   
        if (isLesserThan(oldVersion, "9.4.0")) {
            try {
                upgradeSession.migrateDatabase9_4_0();
            } catch (UpgradeFailedException e) {
                return false;
            }
        }        
        setLastUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
        return true;
    }

    private boolean postUpgrade(String oldVersion, String dbtype) {
        log.debug(">post-upgrade from version: "+oldVersion);
        if (isLesserThan(oldVersion, "6.8.0")) {
            log.error(
                    "Post-upgrade from EJBCA prior to version 6.8.0 is forbidden. Read the EJBCA Upgrade Guide for more information.");
            return false;
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
        if (isLesserThan(oldVersion, "8.3.0")) {
            if (!postMigrateDatabase830()) {
                return false;
            }
            setLastPostUpgradedToVersion("8.3.0");
        }
        
        if (isLesserThan(oldVersion, "9.3.0")) {
            if (!postMigrateDatabase930()) {
                return false;
            }
            setLastPostUpgradedToVersion("9.3.0");
        }
        if (isLesserThan(oldVersion, "9.4.0")) {
            if (!postMigrateDatabase9_4_0()) {
                return false;
            }
            setLastPostUpgradedToVersion("9.4.0");
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
    private boolean postMigrateDatabase781() {
        log.info("Starting post upgrade to 7.8.1");
        List<?> ids;
        try {
            Query query = entityManager.createQuery("SELECT eepd.id FROM EndEntityProfileData eepd");
            ids = query.getResultList();
        } catch (Exception e) {
            log.error("An error occurred when updating data in database table 'EndEntityProfileData': " + e);
            return false;
        }

        for(Object idObject: ids) {
            Integer id = (Integer) idObject;
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
     * Remove the Configuration Checker fom database
     *
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes.
     */
    private boolean postMigrateDatabase830() {
        log.info("Starting post upgrade to 8.3.0");
       
        try {
            if (globalConfigurationSession.findByConfigurationId(CONFIGURATION_CHECKER_CONFIGURATION_ID) != null) {
                globalConfigurationSession.removeConfiguration(authenticationToken, CONFIGURATION_CHECKER_CONFIGURATION_ID);
            }
        } catch (AuthorizationDeniedException e) {
            log.error("Administrator was not authorized to perform post-upgrade, lacks access to Configuration Checker configuration");
            return false;
        }
        
        log.info("Post upgrade to 8.3.0 complete.");
        return true;
    }
    
    /**
     * Remove the Configuration Checker fom database
     *
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes.
     */
    @SuppressWarnings("deprecation")
    private boolean postMigrateDatabase930() {
        log.info("Starting post upgrade to 9.3.0");
        //Remove, from all roles, all user data source related rules. 
        for(Role role : roleSession.getAuthorizedRoles(authenticationToken)) {
            LinkedHashMap<String, Boolean> accessRules = role.getAccessRules();
            List<String> ruleNames = new ArrayList<>(accessRules.keySet());
            for(String rule :  ruleNames) {
                if(rule.startsWith(AccessRulesConstants.USERDATASOURCEBASE) || rule.startsWith(AccessRulesConstants.REGULAR_EDITUSERDATASOURCES)) {
                    accessRules.remove(rule);
                }
            }
            role.setAccessRules(accessRules);
            try {
                roleSession.persistRole(authenticationToken, role);
            } catch (RoleExistsException e) {
                log.error("Role seems to have changed ID while retaining name/namespace or vice versa.");
                return false;
            } catch (AuthorizationDeniedException e) {
                log.error("Administrator was not authorized to perform post-upgrade, lacks access to Configuration Checker configuration");
                return false;
            }
        }       
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        log.info("Post upgrade to 9.3.0 complete.");
        return true;
    }
    
    private boolean postMigrateDatabase9_4_0() {
        log.info("Starting post upgrade to 9.4.0");
        removeEnableIcaoNameChangeFromGlobalConfiguration();
        log.info("Post upgrade to 9.4.0 complete.");
        return true;
    }
    
    /**
     * Removes the enableIcaoNameChange value from GlobalConfiguration post upgrade to 9.4 
     * 
     */
    private void removeEnableIcaoNameChangeFromGlobalConfiguration() {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        //Go straight into the data map and remove it
        LinkedHashMap<Object, Object> data = globalConfiguration.getRawData();
        if (data.containsKey("enableicaocanamechange")) {
            data.remove("enableicaocanamechange");
            globalConfiguration.loadData(data);
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalConfiguration);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("Always allow token was denied access to global configuration.", e);
            }
        }
        
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
        return isLesserThan(getLastPostUpgradedToVersion(), "9.3.0");
    }

    /**
     * Upgrade to EJBCA 6.10.1. 
     * Upgrading System configuration and certificate profiles with CT log label system
     */
    @SuppressWarnings("deprecation")
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
        
        final int caid = DnComponents.stringToBCDNString(subjectdn).hashCode();
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
                final String subjectDn = trustedCert.getSubjectX500Principal().getName();
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
            upgradeSession.fixPartitionedCrls();
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
     * Runs in a new transaction because {@link upgradeIndex} depends on the changes and the release of the metadata locks on CRLData.
     */
    @Override
    public void fixPartitionedCrls() throws UpgradeFailedException {
        // Counting the number of non normal CRLData rows
        final Query query = entityManager.createQuery("SELECT count(*) FROM CRLData WHERE crlPartitionIndex IS NULL OR crlPartitionIndex = 0 ");
        final long countOfRowsToBeNormalized = (long) query.getSingleResult();

        final long startDataNormalization = System.currentTimeMillis();

        // Check whether it is an MSSQL database. If yes, don't normalize in chunks
        final String dbType = DatabaseConfiguration.getDatabaseName();
        if (MSSQL.equals(dbType)) {
            fixPartitionedCrls2(0, true);
        } else {
            // Normalization for non-MSSQL databases is done in chunks in case number of rows are huge in CRLData table.
            // This is to avoid the error "Got error 90 "Message too long" during COMMIT" in Galera clusters
            // See ECA-10712 for more info.
            for (int i = 0; i < countOfRowsToBeNormalized; i += PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE) {
                fixPartitionedCrls2(PARTITIONED_CRLS_NORMALIZE_BATCH_SIZE, false);
            }
            // Do fix the remaining if any
            final Query normalizeData = entityManager.createQuery(
                    "UPDATE CRLData a SET a.crlPartitionIndex = -1 WHERE a.crlPartitionIndex IS NULL OR a.crlPartitionIndex=0");
            log.debug("Executing SQL query: " + normalizeData);
            normalizeData.executeUpdate();
            log.info("Successfully normalized " + countOfRowsToBeNormalized + " rows in CRLData. Completed in "
                    + (System.currentTimeMillis() - startDataNormalization) + " ms.");
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
     * @return true if migration should be considered complete and the <code>lastPostUpgradedToVersion</code>
     * value in the database should be incremented.
     * @throws UpgradeFailedException if upgrade fails
     */
    private void fixPartitionedCrls2(final int limit, final boolean isMSSQL) throws UpgradeFailedException {
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
    @Override
    public IndexUpgradeResult upgradeIndex(final String oldIndexName, final String tableName, final String createIndexQuery) {
        try {
            final long startReindex = System.currentTimeMillis();
            // Unfortunately, "IF EXISTS" and "IF NOT EXISTS" are not supported in index
            // operations in mariadb-connector (tested with version 2.7.3)
            final DatabaseMetaData databaseMetaData = JDBCUtil.getDBConnection().getMetaData();
            String dropIndexString = "DROP INDEX " + oldIndexName;
            // SQL to drop index on PostgreSQL is simply "drop index index_name", but on other DBs you specify the table name
            if (!JDBCUtil.isPostgres(databaseMetaData)) {
                dropIndexString += " ON " + tableName;
            }
            final Query dropCrlDataIndex = entityManager.createNativeQuery(dropIndexString);
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
        } catch (RuntimeException | SQLException | ServiceLocatorException e) {
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
            config.addExtKeyUsage("1.3.6.1.5.5.7.3.36", "EKU_PKIX_DOCUMENTSIGNING");
        }
        log.debug("Added RFC9336 Extended Key Usage to availabe key usages list");
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, config);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
    }
    
    @Override
    public void migrateDatabase830() throws UpgradeFailedException {
        log.debug(">migrateDatabase830");
        // ECA-10671: Migrate ocsp.untilNextUpdate from ocsp.properties into Global Configuration
        //Retrieve the old value, in ms and convert to seconds (smallest granularity
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        
        @SuppressWarnings("deprecation")
        long nextUpdate = OcspConfiguration.getUntilNextUpdate()/1000L;
        globalOcspConfiguration.setDefaultValidityTime(nextUpdate);
        @SuppressWarnings("deprecation")
        long maxAge = OcspConfiguration.getMaxAge()/1000L;
        globalOcspConfiguration.setDefaultResponseMaxAge(maxAge);
        @SuppressWarnings("deprecation")
        boolean useMaxAgeForExpired = OcspConfiguration.getCacheHeaderMaxAge();
        globalOcspConfiguration.setUseMaxValidityForExpiration(useMaxAgeForExpired);
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
        } catch (AuthorizationDeniedException e) {
            log.error("Always allow token was denied authoriation to global configuration table.", e);
        }
    }
    
    @SuppressWarnings("deprecation")
    @Override
    public void migrateDatabase920() throws UpgradeFailedException{
        //Shift various CT-related values from cesecore.properties into Global Configuration
        {
            final GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
            boolean ctCacheEnabled = CesecoreConfiguration.getCTCacheEnabled();
            globalCesecoreConfiguration.setCtCacheEnabled(ctCacheEnabled);
            long ctCacheSize = CesecoreConfiguration.getCTCacheMaxEntries();
            globalCesecoreConfiguration.setCtCacheSize(ctCacheSize);
            long ctCacheCleanupInterval = CesecoreConfiguration.getCTCacheCleanupInterval();
            globalCesecoreConfiguration.setCtCacheCleanupInterval(ctCacheCleanupInterval);
            boolean ctCacheFastFailEnabled = CesecoreConfiguration.getCTFastFailEnabled();
            globalCesecoreConfiguration.setCtCacheFastFailEnabled(ctCacheFastFailEnabled);
            long ctCacheFastFailBackoff = CesecoreConfiguration.getCTFastFailBackOff();
            globalCesecoreConfiguration.setCtCacheFastFailBackoff(ctCacheFastFailBackoff);
            
            try {
                globalConfigurationSession.saveConfiguration(authenticationToken, globalCesecoreConfiguration);
            } catch (AuthorizationDeniedException e) {
                String msg = "Always allow token was denied authoriation to global configuration table.";
                log.error(msg, e);
                throw new UpgradeFailedException(msg, e);
            }
        }
    }

    @Override
    public void migrateDatabase9_4_0() throws UpgradeFailedException {
        //Move ocsp.includecertchain and ocsp.includesignercert from the properties files and into the database configuration
        migrateOcspOptions_9_4_0();
        //Move enableIcaoNameChange from GlobalConfiguration to the new GlobalCaConfiguration row
        migrateCaConfigurationFromGlobalConfig9_4_0();
    }
    
    @SuppressWarnings("deprecation")
    private void migrateOcspOptions_9_4_0() throws UpgradeFailedException {
        GlobalOcspConfiguration globalOcspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        globalOcspConfiguration.setIncludeSigningCertificate(OcspConfiguration.getIncludeSignCert());
        globalOcspConfiguration.setIncludeCertificateChain(OcspConfiguration.getIncludeCertChain());
        
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, globalOcspConfiguration);
        } catch (AuthorizationDeniedException e) {
            String msg = "Always allow token was denied authoriation to global configuration table.";
            log.error(msg, e);
            throw new UpgradeFailedException(msg, e);
        }
    }  
    
    @SuppressWarnings("deprecation")
    private void migrateCaConfigurationFromGlobalConfig9_4_0() throws UpgradeFailedException {
        GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        GlobalCaConfiguration globalCaConfiguration = (GlobalCaConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCaConfiguration.CA_CONFIGURATION_ID);
        globalCaConfiguration.setEnableIcaoCANameChange(globalConfiguration.getEnableIcaoCANameChange());        
        try {
            globalConfigurationSession.saveConfiguration(authenticationToken, globalCaConfiguration);
        } catch (AuthorizationDeniedException e) {
            String msg = "Always allow token was denied authoriation to global configuration table.";
            log.error(msg, e);
            throw new UpgradeFailedException(msg, e);
        }  
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isLesserThan(final String first, final String second) {
        return StringTools.isLesserThan(first, second);
    }

    private class AppendingLogger {

        private final Logger log;

        public AppendingLogger(final Logger log) {
            this.log = log;
        }

        public void trace(final Object msg) {
            log.trace(msg);
            upgradeStatusSingleton.trace(msg);
        }

        public void debug(final Object msg) {
            log.debug(msg);
            upgradeStatusSingleton.debug(msg);
        }

        public void debug(final Object msg, final Throwable throwable) {
            log.debug(msg, throwable);
            upgradeStatusSingleton.debug(msg);
        }

        public void info(final Object msg) {
            log.info(msg);
            upgradeStatusSingleton.info(msg);
        }

        public void warn(final Object msg) {
            log.warn(msg);
            upgradeStatusSingleton.warn(msg);
        }

        public void error(final Object msg) {
            log.error(msg);
            upgradeStatusSingleton.error(msg);
        }

        public void error(final Object msg, final Throwable throwable) {
            log.error(msg, throwable);
            upgradeStatusSingleton.error(msg, throwable);
        }

        public void fatal(final Object msg) {
            log.fatal(msg);
            upgradeStatusSingleton.fatal(msg);
        }

        public boolean isDebugEnabled() {
            return log.isDebugEnabled();
        }

    }
}
