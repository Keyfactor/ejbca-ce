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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleExistsException;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationData;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.core.ejb.hardtoken.HardTokenData;
import org.ejbca.core.ejb.hardtoken.HardTokenIssuerData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRuleTemplate;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.DefaultRoles;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAService;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.upgrade.BasePublisherConverter;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SqlExecutor;

/**
 * The upgrade session bean is used to upgrade the database between EJBCA
 * releases.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UpgradeSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class UpgradeSessionBean implements UpgradeSessionLocal, UpgradeSessionRemote {

    private static final Logger log = Logger.getLogger(UpgradeSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();
    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal upgrade"));
    
    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;

    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private AccessRuleManagementSessionLocal accessRuleManagementSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certProfileSession;
    @EJB
    private ComplexAccessControlSessionLocal complexAccessControlSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private RoleManagementSessionLocal roleMgmtSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;


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

    private GlobalUpgradeConfiguration getGlobalUpgradeConfiguration() {
        return (GlobalUpgradeConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
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
                log.error("Unable to detect version of database content and perform automatic upgrade from the version you are running. Run 'ant upgrade' manually.");
                return false;
            }
        }
        boolean ret = true;
        if (isLesserThan(last, currentVersion)) {
            if (log.isDebugEnabled()) {
                log.debug("Database content version: " + last + " Current application version: " + currentVersion + " -> Starting upgrade.");
            }
            ret = upgradeSession.upgrade(dbType, last, false);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Database content version: " + last + " Current application version: " + currentVersion + " -> Upgrade is not needed.");
            }
        }
        return ret;
    }

    /* TODO: Currently not used, but should be invokable from the Admin GUI */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean performPostUpgrade() {
        final String dbType = DatabaseConfiguration.getDatabaseName();
        final String currentVersion = InternalConfiguration.getAppVersionNumber();
        final String last = getLastPostUpgradedToVersion();
        boolean ret = true;
        if (isLesserThan(last, currentVersion)) {
            ret = upgradeSession.upgrade(dbType, last, false);
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
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
        if (isLesserThan(oldVersion, "3.11")) {
            log.error("Only upgrade from EJBCA 3.11.x is supported in EJBCA 4.0.x and higher.");
            return false;
        }
        // Upgrade between EJBCA 3.11.x and EJBCA 4.0.x to 5.0.x
        if (isLesserThan(oldVersion, "5")) {
        	if (!upgradeSession.migrateDatabase500(dbtype)) {
        		return false;
        	}
            setLastUpgradedToVersion("5.0");
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
            setLastUpgradedToVersion("6.6.0");
        }
        setLastUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
        return true;
    }

    private boolean postUpgrade(String oldVersion, String dbtype) {
        log.debug(">post-upgrade from version: "+oldVersion);
        if (isLesserThan(oldVersion, "3.11")) {
            log.error("Upgrades directly from versions 3.10.x or earlier are note supported by this version of EJBCA. Please upgrade to a version of 4.0.x first.");
            return false;
        }
        // Upgrade database change between EJBCA 3.11.x and EJBCA 4.0.x if needed
        if (isLesserThan(oldVersion,"4")) {
            if (!postMigrateDatabase4_0_0()) {
                return false;
            }
            setLastPostUpgradedToVersion("4.0");
        }
        // Upgrade database change between EJBCA 4.0.x and EJBCA 5.0.x if needed, and previous post-upgrade succeeded
        if (isLesserThan(oldVersion, "5")) {
            if (!postMigrateDatabase500(dbtype)) {
                return false;
            }
            setLastPostUpgradedToVersion("5.0");
        }
        if (isLesserThan(oldVersion, "6.3.2")) {
            if (!postMigrateDatabase632()) {
                return false;
            }
            setLastPostUpgradedToVersion("6.3.2");
        }
        // NOTE: If you add additional post upgrade tasks here, also modify isPostUpgradeNeeded()
        //setLastPostUpgradedToVersion(InternalConfiguration.getAppVersionNumber());
        return true;
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean isPostUpgradeNeeded() {
        return isLesserThan(getLastPostUpgradedToVersion(), "6.3.2");
    }

    /**
     * Called from other migrate methods, don't call this directly, call from an
     * interface-method
     * 
     */
    private boolean migrateDatabase(String resource) {
        // Fetch the resource file with SQL to modify the database tables
        InputStream in = this.getClass().getResourceAsStream(resource);
        if (in == null) {
            log.error("Can not read resource for database '" + resource + "', this database probably does not need table definition changes.");
            // no error
            return true;
        }
        // Migrate database tables to new columns etc
        Connection con = null;
        log.info("Start migration of database.");
        try {
            InputStreamReader inreader = new InputStreamReader(in);
            con = JDBCUtil.getDBConnection();
            SqlExecutor sqlex = new SqlExecutor(con, false);
            sqlex.runCommands(inreader);
        } catch (SQLException e) {
            log.error("SQL error during database migration: ", e);
            return false;
        } catch (IOException e) {
            log.error("IO error during database migration: ", e);
            return false;
        } finally {
            JDBCUtil.close(con);
        }
        log.info("Finished migration of database.");
        return true;
    }

    /**
     * (ECA-200:) In EJB 2.1 JBoss CMP used it's own serialization method for all Object/BLOB fields.
     * 
     * This affects the following entity fields:
     * - CertificateProfileData.data
     * - HardTokenData.data
     * - HardTokenIssuerData.data
     * - LogConfigurationData.logConfiguration
     * - AdminPreferencesData.data
     * - EndEntityProfileData.data
     * - GlobalConfigurationData.data
     * 
     * NOTE: You only need to run this if you upgrade a JBoss installation.
     */
    private boolean postMigrateDatabase4_0_0() {
    	log.error("(this is not an error) Starting post upgrade from EJBCA 3.11.x to EJBCA 4.0.x");
    	boolean ret = true;
    	upgradeSession.postMigrateDatabase400SmallTables();	// Migrate small tables in a new transaction 
    	log.info(" Processing HardTokenData entities.");
    	log.info(" - Building a list of entities.");
    	final List<String> tokenSNs = HardTokenData.findAllTokenSN(entityManager);
    	int position = 0;
    	final int chunkSize = 1000;
    	while (position < tokenSNs.size()) {
        	log.info(" - Processing entity " + position + " to " + Math.min(position+chunkSize-1, tokenSNs.size()-1) + ".");
        	// Migrate HardTokenData table in chunks, each running in a new transaction
    		upgradeSession.postMigrateDatabase400HardTokenData(getSubSet(tokenSNs, position, chunkSize));
    		position += chunkSize;
    	}
    	log.error("(this is not an error) Finished post upgrade from EJBCA 3.11.x to EJBCA 4.0.x with result: "+ret);
        return ret;
    }
        
    /** @return a subset of the source list with index as its first item and index+count-1 as its last. */
    private <T> List<T> getSubSet(final List<T> source, final int index, final int count) {
    	List<T> ret = new ArrayList<T>(count);
    	for (int i=0; i<count; i++) {
            if (source.size() > (index + i)) {
                ret.add(source.get(index + i));

            }
    	}
    	return ret;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public void postMigrateDatabase400SmallTables() {
    	// LogConfiguration removed for EJBCA 5.0, so no upgrade of that needed
    	log.info(" Processing CertificateProfileData entities.");
    	final List<CertificateProfileData> cpds = CertificateProfileData.findAll(entityManager);
    	for (CertificateProfileData cpd : cpds) {
    		// When the wrong class is given it can either return null, or throw an exception
    		HashMap h = getDataUnsafe(cpd.getDataUnsafe());
    		cpd.setDataUnsafe(h);
    	}
    	log.info(" Processing HardTokenIssuerData entities.");
    	final List<HardTokenIssuerData> htids = HardTokenIssuerData.findAll(entityManager);
    	for (HardTokenIssuerData htid : htids) {
    		HashMap h = getDataUnsafe(htid.getDataUnsafe());
    		htid.setDataUnsafe(h);
    	}
    	log.info(" Processing AdminPreferencesData entities.");
    	final List<AdminPreferencesData> apds = AdminPreferencesData.findAll(entityManager);
    	for (AdminPreferencesData apd : apds) {
    		HashMap h = getDataUnsafe(apd.getDataUnsafe());
    		apd.setDataUnsafe(h);
    	}
    	log.info(" Processing EndEntityProfileData entities.");
    	final List<EndEntityProfileData> eepds = EndEntityProfileData.findAll(entityManager);
    	for (EndEntityProfileData eepd : eepds) {
    		HashMap h = getDataUnsafe(eepd.getDataUnsafe());
    		eepd.setDataUnsafe(h);
    	}
    	log.info(" Processing GlobalConfigurationData entities.");
    	GlobalConfigurationData gcd = globalConfigurationSession.findByConfigurationId(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
		HashMap h = getDataUnsafe(gcd.getDataUnsafe());
    	gcd.setDataUnsafe(h);
    }

	/**
	 * @param cpd
	 * @return
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
    private HashMap getDataUnsafe(Serializable s) {
		HashMap h = null; 
		try {
			h = JBossUnmarshaller.extractObject(LinkedHashMap.class, s);
			if (h == null) {
				h = new LinkedHashMap(JBossUnmarshaller.extractObject(HashMap.class, s));
			}
		} catch (ClassCastException e) {
			h = new LinkedHashMap(JBossUnmarshaller.extractObject(HashMap.class, s));
		}
		return h;
	}
    
    @SuppressWarnings("rawtypes")
    @Override
    public void postMigrateDatabase400HardTokenData(List<String> subSet) {
    	for (String tokenSN : subSet) {
    		HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokenSN);
    		if (htd != null) {
        		HashMap h = getDataUnsafe(htd);
        		htd.setDataUnsafe(h);
    		} else {
    	    	log.warn("Hard token was removed during processing. Ignoring token with serial number '" + tokenSN + "'.");
    		}
    	}
    }

    /**
     * In EJBCA 5.0 we have introduced a new authorization rule system.
     * The old "/super_administrator" rule is replaced by a rule to access "/" (StandardRules.ROLE_ROOT.resource()) with recursive=true.
     * therefore we must insert a new access rule in the database in all roles that have super_administrator access.
     * 
     * We have also added a column to the table AdminEntityData: tokenType
     * 
     * @param dbtype A string representation of the actual database.
     * 
     */
    @SuppressWarnings({ "unchecked", "deprecation" })
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)   // Until our roles API can handle transactions properly
    @Override
    public boolean migrateDatabase500(String dbtype) {
    	log.error("(this is not an error) Starting upgrade from ejbca 4.0.x to ejbca 5.0.x");
    	boolean ret = true;
    	
    	AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.migrateDatabase500"));

    	//Upgrade database
    	migrateDatabase("/400_500/400_500-upgrade-"+dbtype+".sql");
    	
    	final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration) 
    	        globalConfigurationSession.getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID );
    	// fix CAs that don't have classpath for extended CA services
    	Collection<Integer> caids = caSession.getAllCaIds();
    	for (Integer caid : caids) {
    		try {
				CA ca = caSession.getCAForEdit(admin, caid);
				if (ca.getCAType() == CAInfo.CATYPE_X509) {
					Collection<Integer> extendedServiceTypes = ca.getExternalCAServiceTypes();
					for (Integer type : extendedServiceTypes) {
						ExtendedCAServiceInfo info = ca.getExtendedCAServiceInfo(type);
						if (info == null) {
							@SuppressWarnings("rawtypes")
                            HashMap data = ca.getExtendedCAServiceData(type);
							switch (type) {
							case ExtendedCAServiceTypes.TYPE_CMSEXTENDEDSERVICE:
								data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, CmsCAService.class.getName());
								ca.setExtendedCAServiceData(type, data);
								log.info("Updating extended CA service of type "+type+" with implementation class "+CmsCAService.class.getName());
								break;
							case ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE:
								data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, HardTokenEncryptCAService.class.getName());
								ca.setExtendedCAServiceData(type, data);
								log.info("Updating extended CA service of type "+type+" with implementation class "+HardTokenEncryptCAService.class.getName());
								break;
							case ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE:
								data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, KeyRecoveryCAService.class.getName());
								ca.setExtendedCAServiceData(type, data);
								log.info("Updating extended CA service of type "+type+" with implementation class "+KeyRecoveryCAService.class.getName());
								break;
							default:
								break;
							}
						} else {
							// If we can't get info for the HardTokenEncrypt or KeyRecovery service it means they don't exist 
							// as such in the database, but was hardcoded before. We need to create them from scratch
							switch (type) {
							case ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE:
								HardTokenEncryptCAServiceInfo htinfo = new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE);
								HardTokenEncryptCAService htservice = new HardTokenEncryptCAService(htinfo);
								log.info("Creating extended CA service of type "+type+" with implementation class "+HardTokenEncryptCAService.class.getName());
								ca.setExtendedCAService(htservice);
								break;
							case ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE:
								KeyRecoveryCAServiceInfo krinfo = new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE);
								KeyRecoveryCAService krservice = new KeyRecoveryCAService(krinfo);
								log.info("Creating extended CA service of type "+type+" with implementation class "+KeyRecoveryCAService.class.getName());
								ca.setExtendedCAService(krservice);
								break;
							default:
								break;
							}
						}
					}
					// If key recovery and hard token encrypt service does not exist, we have to create them
					CAInfo cainfo = ca.getCAInfo();
					Collection<ExtendedCAServiceInfo> extendedcaserviceinfos = new ArrayList<>();
					if (!extendedServiceTypes.contains(ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE)) {
						log.info("Adding new extended CA service of type "+ExtendedCAServiceTypes.TYPE_HARDTOKENENCEXTENDEDSERVICE+" with implementation class "+HardTokenEncryptCAService.class.getName());
						extendedcaserviceinfos.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
					}
					if (!extendedServiceTypes.contains(ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE)) {
						log.info("Adding new extended CA service of type "+ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE+" with implementation class "+KeyRecoveryCAService.class.getName());							
						extendedcaserviceinfos.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
					}
					if (!extendedcaserviceinfos.isEmpty()) {
						cainfo.setExtendedCAServiceInfos(extendedcaserviceinfos);
						final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
						ca.updateCA(cryptoToken, cainfo, cceConfig);
					}
					// Finally store the upgraded CA
					caSession.editCA(admin, ca, true);
				}
			} catch (CADoesntExistsException e) {
				log.error("CA does not exist during upgrade: "+caid, e);
			} catch (AuthorizationDeniedException e) {
				log.error("Authorization denied to CA during upgrade: "+caid, e);
			} catch (InvalidAlgorithmException e) {
                log.error("Illegal Crypto Token algortihm during upgrade. CA Id: "+caid, e);
            }
    	}
    	/*
    	 *  Upgrade super_administrator access rules to be a /* rule, so super_administrators can still do everything.
    	 *  
    	 * Also, set token types to the standard X500 principal if otherwise null. Since token types is a new concept, 
         * all existing aspects/admin entities must be of this type
    	 */
    	Collection<RoleData> roles = roleAccessSession.getAllRoles();
    	for (RoleData role : roles) {
    	    Collection<AccessUserAspectData> updatedUsers = new ArrayList<>();
    	    for(AccessUserAspectData userAspect : role.getAccessUsers().values()) {
    	        if(userAspect.getTokenType() == null) {
    	            userAspect.setTokenType(X509CertificateAuthenticationToken.TOKEN_TYPE);
    	            updatedUsers.add(userAspect);
    	        }
    	    }
    	    try {
                role = roleMgmtSession.addSubjectsToRole(admin, role, updatedUsers);
            } catch (RoleNotFoundException e) {
                log.error("Not possible to edit subjects for role: "+role.getRoleName(), e);
            } catch (AuthorizationDeniedException e) {
                log.error("Not possible to edit subjects for role: "+role.getRoleName(), e);
            }
    
    	    //The old "/super_administrator" rule is replaced by a rule to access "/" (StandardRules.ROLE_ROOT.resource()) with recursive=true.
    	    // therefore we must insert a new access rule in the database in all roles that have super_administrator access.
    		final Map<Integer, AccessRuleData> rulemap = role.getAccessRules();
    		final Collection<AccessRuleData> rules = rulemap.values();
    		for (AccessRuleData rule : rules) {
    			if (StringUtils.equals("/super_administrator", rule.getAccessRuleName()) && 
    					rule.getInternalState().equals(AccessRuleState.RULE_ACCEPT)) {
    				// Now we add a new rule
    				final AccessRuleData slashRule = new AccessRuleData(role.getRoleName(), StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
    				log.info("Replacing all rules of the role '"+role.getRoleName()+"' with the rule '"+slashRule+"' since the role contained the '"+StandardRules.ROLE_ROOT+"' rule.");
    				final Collection<AccessRuleData> newrules = new ArrayList<>();
    				newrules.add(slashRule);
    				try {
    					// if one of the rules was "super administrator" then all other rules of the role was disregarded in version<5. So now it should only be the '/' rule for the role.
    					upgradeSession.replaceAccessRulesInRoleNoAuth(admin, role, newrules);
    				} catch (RoleNotFoundException e) {
    					log.error("Not possible to add new access rule to role: "+role.getRoleName(), e);
    				}  		    		
    				break; // no need to continue with this role
    			}
    		}
    	}
    	
    	accessTreeUpdateSession.signalForAccessTreeUpdate();
    	accessControlSession.forceCacheExpire();
    	
    	log.error("(this is not an error) Finished upgrade from ejbca 4.0.x to ejbca 5.0.x with result: "+ret);
        return ret;
    }


    @Deprecated 
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public RoleData replaceAccessRulesInRoleNoAuth(final AuthenticationToken authenticationToken, final RoleData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException {
        
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        Map<Integer, AccessRuleData> rulesFromResult = result.getAccessRules();
        Map<Integer, AccessRuleData> rulesToResult = new HashMap<>();
        //Lists for logging purposes.
        Collection<AccessRuleData> newRules = new ArrayList<>();
        Collection<AccessRuleData> changedRules = new ArrayList<>();
        for (AccessRuleData rule : accessRules) {
            if (AccessRuleData.generatePrimaryKey(role.getRoleName(), rule.getAccessRuleName()) != rule.getPrimaryKey()) {
                throw new Error("Role " + role.getRoleName() + " did not match up with the role that created this rule.");
            }
            Integer ruleKey = rule.getPrimaryKey();
            if (rulesFromResult.containsKey(ruleKey)) {
                AccessRuleData oldRule = rulesFromResult.get(ruleKey);
                if(!oldRule.equals(rule)) {
                    changedRules.add(oldRule);
                }
                AccessRuleData newRule = accessRuleManagementSession.setState(rule, rule.getInternalState(), rule.getRecursive());
                rulesFromResult.remove(ruleKey);
                rulesToResult.put(newRule.getPrimaryKey(), newRule);         
            } else {
                try {
                    newRules.add(accessRuleManagementSession.createRule(rule.getAccessRuleName(), result.getRoleName(), rule.getInternalState(),
                            rule.getRecursive()));
                } catch (AccessRuleExistsException e) {
                    throw new Error("Access rule exists, but wasn't found in persistence in previous call.", e);
                }
                rulesToResult.put(rule.getPrimaryKey(), rule);
            }

        }
        logAccessRulesAdded(authenticationToken, role.getRoleName(), newRules);
        logAccessRulesChanged(authenticationToken, role.getRoleName(), changedRules);

        //And for whatever remains:
        accessRuleManagementSession.remove(rulesFromResult.values());
        result.setAccessRules(rulesToResult);
        result = entityManager.merge(result);
        logAccessRulesRemoved(authenticationToken, role.getRoleName(), rulesFromResult.values());
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();

        return result;
    }
    
    
    /**
     * Upgrade access rules such that every role that already has access to /system_functionality/edit_systemconfiguration 
     * will also have access to the new access rule /system_functionality/edit_available_extended_key_usages
     * 
     * @return true if the upgrade was successful and false otherwise
     */
    private boolean addEKUAndCustomCertExtensionsAccessRulestoRoles() {
        Collection<RoleData> roles = new ArrayList<>(roleAccessSession.getAllRoles());
        for (RoleData role : roles) {
            final Map<Integer, AccessRuleData> rulemap = role.getAccessRules();
            final Collection<AccessRuleData> rules = new ArrayList<>(rulemap.values());
            for (AccessRuleData rule : rules) {
                if (StringUtils.equals(StandardRules.SYSTEMCONFIGURATION_EDIT.resource(), rule.getAccessRuleName()) && 
                        rule.getInternalState().equals(AccessRuleState.RULE_ACCEPT)) {
                    // Now we add a new rule
                    final Collection<AccessRuleData> newrules = new ArrayList<>();
                    final AccessRuleData editAvailableEKURule = new AccessRuleData(role.getRoleName(), StandardRules.EKUCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false);
                    final AccessRuleData editCustomCertExtensionsRule = new AccessRuleData(role.getRoleName(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource(), AccessRuleState.RULE_ACCEPT, false);
                    newrules.add(editAvailableEKURule);
                    newrules.add(editCustomCertExtensionsRule);
                    try {
                        addAccessRulesToRole(role, newrules);
                        log.info("Added rule '" + editAvailableEKURule.toString() + "' to role '"+role.getRoleName()+"' since the role contained the '"+StandardRules.SYSTEMCONFIGURATION_EDIT+"' rule.");
                    } catch (Exception e) {
                        log.error("Not possible to add new access rule to role: "+role.getRoleName(), e);
                    }                
                }
            }
        }
        
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();
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
            log.error("Recieved an AuthorizationDeniedException even though AlwaysAllowLocalAuthenticationToken is used. " + e.getLocalizedMessage());
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
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    private void addReadOnlyRules640() throws UpgradeFailedException {
        try {
            // Any roles that had access to /ca_functionality/basic_functions/activate_ca or just /ca_functionality/ (+recursive) 
            // should be given access to /ca_functionality/view_ca
            Set<RoleData> viewCaRoles = new HashSet<>(roleMgmtSession.getAuthorizedRoles(AccessRulesConstants.REGULAR_ACTIVATECA, false));
            viewCaRoles.addAll(roleMgmtSession.getAuthorizedRoles(StandardRules.CAFUNCTIONALITY.resource(), true));
            for (RoleData role : viewCaRoles) {
                //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), StandardRules.CAVIEW.resource(), AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                    addAccessRulesToRole(role, Arrays.asList(newRule));
                }
            }
            // Next, any roles with access to /ca_functionality/edit_certificate_profiles should have be given access to /ca_functionality/view_certificate_profiles
            List<RoleData> certificateProfileRoles = roleMgmtSession.getAuthorizedRoles(StandardRules.CERTIFICATEPROFILEEDIT.resource(), false);
            for (RoleData role : certificateProfileRoles) {
              //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), StandardRules.CERTIFICATEPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                addAccessRulesToRole(role,
                        Arrays.asList(newRule));
                }
            }
            // Any roles with access to /ca_functionality/edit_publisher should be given /ca_functionality/view_publisher
            List<RoleData> publisherRoles = roleMgmtSession.getAuthorizedRoles(AccessRulesConstants.REGULAR_EDITPUBLISHER, false);
            for (RoleData role : publisherRoles) {
                //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), AccessRulesConstants.REGULAR_VIEWPUBLISHER, AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                addAccessRulesToRole(role,
                        Arrays.asList(newRule));
                }
            }
            // Any roles with access to /ra_functionality/edit_end_entity_profiles should be given /ra_functionality/view_end_entity_profiles
            List<RoleData> endEntityProfileRoles = roleMgmtSession.getAuthorizedRoles(AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, false);
            for (RoleData role : endEntityProfileRoles) {
              //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES, AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                addAccessRulesToRole(role,
                        Arrays.asList(newRule));
                }
            }
            // Any roles with access to "/" should be given /services/edit, /services/view and /peer/view (+recursive)
            List<RoleData> rootAccessRoles = roleMgmtSession.getAuthorizedRoles(StandardRules.ROLE_ROOT.resource(), false);
            for (RoleData role : rootAccessRoles) {
              //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                ArrayList<AccessRuleData> accessRulesList = new ArrayList<>();
                AccessRuleData servicesEdit = new AccessRuleData(role.getRoleName(), AccessRulesConstants.SERVICES_EDIT, AccessRuleState.RULE_ACCEPT,
                        false);
                AccessRuleData servicesView = new AccessRuleData(role.getRoleName(), AccessRulesConstants.SERVICES_VIEW, AccessRuleState.RULE_ACCEPT,
                        false);
                AccessRuleData peerView = new AccessRuleData(role.getRoleName(), AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW,
                        AccessRuleState.RULE_ACCEPT, true);
                if (!role.getAccessRules().containsValue(peerView)) {
                    accessRulesList.add(peerView);
                }
                if (!role.getAccessRules().containsValue(servicesEdit)) {
                    accessRulesList.add(servicesEdit);
                }
                if (!role.getAccessRules().containsValue(servicesView)) {
                    accessRulesList.add(servicesView);
                }
                addAccessRulesToRole(role, accessRulesList);
            }           
            // Any roles with access to /internalkeybinding should be given /internalkeybinding/view (+recursive)
            List<RoleData> keybindingProfileRoles = roleMgmtSession.getAuthorizedRoles(InternalKeyBindingRules.BASE.resource(), false);
            for (RoleData role : keybindingProfileRoles) {
                //Skip if superadmin 
                if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                    continue;
                }
                //Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), InternalKeyBindingRules.VIEW.resource(), AccessRuleState.RULE_ACCEPT, true);
                if (!role.getAccessRules().containsValue(newRule)) {
                addAccessRulesToRole(role,
                        Arrays.asList(newRule));
                }
            }
        } catch (RoleNotFoundException e) {
            throw new UpgradeFailedException("Upgrade failed, for some reason retrieved role does not exist in database.", e);
        }
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
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    private void addReadOnlyRules642() throws UpgradeFailedException {
        for (RoleData role : roleAccessSession.getAllRoles()) {
            //Skip if superadmin 
            if(role.hasAccessToRule(StandardRules.ROLE_ROOT.resource(), true)) {
                continue;
            }
            //Find roles which correspond to the old Auditor
            Collection<AccessRuleTemplate> newRulesFor642 = new ArrayList<>();
            newRulesFor642.add(new AccessRuleTemplate(StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false));
            newRulesFor642.add(new AccessRuleTemplate(StandardRules.EKUCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false));
            newRulesFor642.add(new AccessRuleTemplate(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT, false));
            newRulesFor642.add(new AccessRuleTemplate(StandardRules.VIEWROLES.resource(), AccessRuleState.RULE_ACCEPT, false));
            newRulesFor642.add(new AccessRuleTemplate(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT, false));

            //If role is the old auditor from 6.4.0
            String rolename = role.getRoleName();
            try {            
                if (matches640Auditor(role)) {
                    List<AccessRuleData> newAccessRules = new ArrayList<>();
                    newAccessRules.add(new AccessRuleData(rolename, StandardRules.SYSTEMCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT,
                            false));
                    newAccessRules.add(new AccessRuleData(rolename, StandardRules.EKUCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT,
                            false));
                    newAccessRules.add(new AccessRuleData(rolename, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT,
                            false));
                    newAccessRules.add(new AccessRuleData(rolename, StandardRules.VIEWROLES.resource(), AccessRuleState.RULE_ACCEPT,
                            false));
                    newAccessRules.add(new AccessRuleData(rolename, AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRuleState.RULE_ACCEPT,
                            false));
                    roleMgmtSession.addAccessRulesToRole(authenticationToken, role, newAccessRules);
                } else {
                    List<AccessRuleData> newAccessRules = new ArrayList<>();
                    //Not an Auditor, but there may be other cases where we should grant access. 
                    if (role.hasAccessToRule(StandardRules.SYSTEMCONFIGURATION_EDIT.resource())) {
                        newAccessRules.add(new AccessRuleData(rolename, StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                                AccessRuleState.RULE_ACCEPT, false));
                    }
                    if (role.hasAccessToRule(StandardRules.EKUCONFIGURATION_EDIT.resource())) {
                        newAccessRules.add(new AccessRuleData(rolename, StandardRules.EKUCONFIGURATION_VIEW.resource(), AccessRuleState.RULE_ACCEPT,
                                false));
                    }
                    if (role.hasAccessToRule(StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource())) {
                        newAccessRules.add(new AccessRuleData(rolename, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(),
                                AccessRuleState.RULE_ACCEPT, false));
                    }
                    if (role.hasAccessToRule(StandardRules.EDITROLES.resource())) {
                        newAccessRules.add(new AccessRuleData(rolename, StandardRules.VIEWROLES.resource(),
                                AccessRuleState.RULE_ACCEPT, false));
                    }                   
                    roleMgmtSession.addAccessRulesToRole(authenticationToken, role, newAccessRules);
                }           
            } catch (RoleNotFoundException e) {
                throw new UpgradeFailedException("Newly accessed role was not available", e);
            } catch (AuthorizationDeniedException e) {
                throw new UpgradeFailedException("Internal admin was denied access.", e);
            }
        }
    }
    
    private boolean matches640Auditor(RoleData role) {
        // We'll tolerate that the role has some external rules added to it
        // We won't use the method in defaultRoles, because it presumes knowledge of external rules. 
        //So, simply verify that all rules but the new ones are in the selected role. 
        Set<String> ignoreRules = new HashSet<>(Arrays.asList(StandardRules.SYSTEMCONFIGURATION_VIEW.resource(),
                StandardRules.EKUCONFIGURATION_VIEW.resource(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource(), StandardRules.VIEWROLES.resource(),
                AccessRulesConstants.REGULAR_VIEWENDENTITY));
        for (AccessRuleTemplate auditorRule : DefaultRoles.AUDITOR.getRuleSet()) {
            if (!ignoreRules.contains(auditorRule.getAccessRuleName()) && !role.hasAccessToRule(auditorRule.getAccessRuleName())) {
                return false;
            }
        }
        for(String ignoreRule : ignoreRules) {
            if(role.hasAccessToRule(ignoreRule)) {
                //We're already a 6.4.2 auditor
                return false;
            }
        }
        return true;
    }

    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    private RoleData addAccessRulesToRole(final RoleData role, final Collection<AccessRuleData> accessRules) throws RoleNotFoundException { 
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }
        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.AddNewAccessRulestoRoles"));
        try {
            roleMgmtSession.addAccessRulesToRole(admin, result, accessRules);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("Always allow token was denied access.", e);
        }
        logAccessRulesAdded(admin, role.getRoleName(), accessRules);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();
        return result;
    }
    
    private void logAccessRulesAdded(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> addedRules) {
        if (addedRules.size() > 0) {
            StringBuilder addedRulesMsg = new StringBuilder();
            for(AccessRuleData addedRule : addedRules) {
                addedRulesMsg.append("[" + addedRule.toString() + "]");
            }            
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessrulesadded", rolename, addedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
    }
    
    private void logAccessRulesChanged(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> changedRules) {
        if (changedRules.size() > 0) {
            StringBuilder changedRulesMsg = new StringBuilder();
            for(AccessRuleData changedRule : changedRules) {
                changedRulesMsg.append("[" + changedRule.toString() + "]");
            }
       
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessruleschanged", rolename, changedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
    }

    private void logAccessRulesRemoved(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> removedRules) {
        if (removedRules.size() > 0) {
            StringBuilder removedRulesMsg = new StringBuilder();
            for(AccessRuleData removedRule : removedRules) {
                removedRulesMsg.append("[" + removedRule.getAccessRuleName() + "]");
            }      
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessrulesremoved", rolename, removedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
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
            return false;
        }
        log.error("(this is not an error) Starting post upgrade to 6.3.2");
        //Find all publishers, make copies of them using the new publisher class. 
        Map<Integer, BasePublisher> allPublishers = publisherSession.getAllPublishers();
        Map<Integer, String> publisherNames = publisherSession.getPublisherIdToNameMap();
        BasePublisherConverter publisherFactory;
        try {
            publisherFactory = (BasePublisherConverter) Class.forName("org.ejbca.va.publisher.EnterpriseValidationAuthorityPublisherFactoryImpl").newInstance();
        } catch (InstantiationException e) {
            //Shouldn't happen since we've already checked that we're running Enterprise
            throw new IllegalStateException(e);
        } catch (IllegalAccessException e) {
            //Shouldn't happen since we've already checked that we're running Enterprise
            throw new IllegalStateException(e);
        } catch (ClassNotFoundException e) {
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
     * 
     * @throws UpgradeFailedException if upgrade fails (rolls back)
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void migrateDatabase660() throws UpgradeFailedException {
        try {
            // Any roles with access to /ca_functionality/view_certifcate_profiles should be given /ca_functionality/view_approval_profiles
            List<RoleData> endEntityProfileRoles = roleMgmtSession.getAuthorizedRoles(StandardRules.CERTIFICATEPROFILEVIEW.resource(), false);
            for (RoleData role : endEntityProfileRoles) {
                // Skip if CA Admin or SuperAdmin
                if (role.hasAccessToRule(StandardRules.CAFUNCTIONALITY.resource(), true)) {
                    continue;
                }
                // Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), StandardRules.APPROVALPROFILEVIEW.resource(), AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                    addAccessRulesToRole(role, Arrays.asList(newRule));
                }
            }
            // Any roles with access to /ca_functionality/edit_certificate_profiles should be given /ca_functionality/edit_approval_profiles
            endEntityProfileRoles = roleMgmtSession.getAuthorizedRoles(StandardRules.CERTIFICATEPROFILEEDIT.resource(), false);
            for (RoleData role : endEntityProfileRoles) {
                // Skip if CA Admin or SuperAdmin
                if (role.hasAccessToRule(StandardRules.CAFUNCTIONALITY.resource(), true)) {
                    continue;
                }
                // Find 
                AccessRuleData newRule = new AccessRuleData(role.getRoleName(), StandardRules.APPROVALPROFILEEDIT.resource(), AccessRuleState.RULE_ACCEPT, false);
                if (!role.getAccessRules().containsValue(newRule)) {
                    addAccessRulesToRole(role, Arrays.asList(newRule));
                }
            }
        } catch (RoleNotFoundException e) {
            throw new UpgradeFailedException("Upgrade failed, for some reason retrieved role does not exist in database.", e);
        }
    }
    
    /**
     * In EJBCA 5.0 we have changed classname for CertificatePolicy.
     * In order to allow us to remove the legacy class in the future we want to upgrade all certificate profiles to use the new classname
     * 
     * In order to be able to create new Roles we also need to remove the long deprecated database column caId, otherwise
     * we will get a database error during insert. Reading works fine though, so this is good for a post upgrade in order
     * to allow for 100% uptime upgrades.
     */
    private boolean postMigrateDatabase500(String dbtype) {
        log.error("(this is not an error) Starting post upgrade from EJBCA 4.0.x to ejbca 5.0.x");
        boolean ret = true;

        AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.postMigrateDatabase500"));

    	// post-upgrade "change CertificatePolicy from ejbca class to cesecore class in certificate profiles that have that defined.
        Map<Integer, String> map = certProfileSession.getCertificateProfileIdToNameMap();
        Set<Integer> ids = map.keySet();
        for (Integer id : ids) {
            CertificateProfile profile = certProfileSession.getCertificateProfile(id);
            final List<CertificatePolicy> policies = profile.getCertificatePolicies();
            if ((policies != null) && (!policies.isEmpty())) {
                List<CertificatePolicy> newpolicies = getNewPolicies(policies);
                // Set the updated policies, replacing the old
                profile.setCertificatePolicies(newpolicies);
                try {
                    final String profName = map.get(id);
                    log.info("Upgrading CertificatePolicy of certificate profile '"+profName+"'. This profile can no longer be used with EJBCA 4.x.");
                    certProfileSession.changeCertificateProfile(admin, profName, profile);
                } catch (AuthorizationDeniedException e) {
                    log.error("Error upgrading certificate policy: ", e);
                }
            }
        }
        // post-upgrade "change CertificatePolicy from ejbca class to cesecore class in CAs profiles that have that defined?
        // fix CAs that don't have classpath for extended CA services
        Collection<Integer> caids = caSession.getAllCaIds();
        for (Integer caid : caids) {
            try {
                CA ca = caSession.getCAForEdit(admin, caid);
                if (ca.getCAType() == CAInfo.CATYPE_X509) {
                    try {
                        X509CA x509ca = (X509CA)ca;
                        final List<CertificatePolicy> policies = x509ca.getPolicies();
                        if ((policies != null) && (!policies.isEmpty())) {
                            List<CertificatePolicy> newpolicies = getNewPolicies(policies);
                            // Set the updated policies, replacing the old
                            x509ca.setPolicies(newpolicies);
                            // Finally store the upgraded CA
                            log.info("Upgrading CertificatePolicy of CA '"+ca.getName()+"'. This CA can no longer be used with EJBCA 4.x.");
                            caSession.editCA(admin, ca, true);
                        }
                    } catch (ClassCastException e) {
                        log.error("CA is not of type X509CA: "+caid+", "+ca.getClass().getName());
                    }
                }
            } catch (CADoesntExistsException e) {
                log.error("CA does not exist during upgrade: "+caid, e);
            } catch (AuthorizationDeniedException e) {
                log.error("Authorization denied to CA during upgrade: "+caid, e);
            } 
        }
        
    	boolean exists = upgradeSession.checkColumnExists500();
    	if (exists) {
    		ret = migrateDatabase("/400_500/400_500-post-upgrade-"+dbtype+".sql");			
    	}

        // Creates a super admin role for Cli usage. post-upgrade to remove caId column must have been run in order
    	// for this command to succeed. 
    	// In practice this means that when upgrading from EJBCA 4.0 you can not use the CLI in 5.0 before you
    	// have finished migrating all your 4.0 nodes and run post-upgrade.
        complexAccessControlSession.createSuperAdministrator();
    
        //Remove all old roles, should remove associated aspects and rules as well.
        removeOldRoles500();

    	log.error("(this is not an error) Finished post upgrade from EJBCA 4.0.x to EJBCA 5.0.x with result: "+ret);
	
        return ret;
    }
    
    /**
     * This method removes the following now unused roles:
     *                                                  DEFAULT
     *                                                  Temporary Super Administrator Group
     *                                                  Public Web Users
     */
    private void removeOldRoles500() {
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.removeOldRoles"));
        final String defaultRoleName = "DEFAULT";
        final String tempSuperAdminRoleName = "Temporary Super Administrator Group";
        final String publicWebRoleName = "Public Web Users";
        try {
            RoleData defaultRole = roleAccessSession.findRole(defaultRoleName);
            if (defaultRole != null) {
                try {
                    roleMgmtSession.remove(admin, defaultRole);
                } catch (RoleNotFoundException e) {
                    //Ignore, can't happen
                }
            }
            RoleData tempSuperAdminRole = roleAccessSession.findRole(tempSuperAdminRoleName);
            if (tempSuperAdminRole != null) {
                try {
                    roleMgmtSession.remove(admin, tempSuperAdminRole);
                } catch (RoleNotFoundException e) {
                    //Ignore, can't happen
                }
            }
            RoleData publicWebRole = roleAccessSession.findRole(publicWebRoleName);
            if (publicWebRole != null) {
                try {
                    roleMgmtSession.remove(admin, publicWebRole);
                } catch (RoleNotFoundException e) {
                    //Ignore, can't happen
                }
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException("AlwaysAllowLocalAuthenticationToken should not have been denied authorization");

        }
    }

    private List<CertificatePolicy> getNewPolicies(final List<CertificatePolicy> policies) {
        final List<CertificatePolicy> newpolicies = new ArrayList<>();
        for(final Iterator<?> it = policies.iterator(); it.hasNext(); ) {
            Object o = it.next();
            try {
                final CertificatePolicy policy = (CertificatePolicy)o;
                // This was a new policy (org.cesecore), just add it
                newpolicies.add(policy);
            } catch (ClassCastException e) {
                // Here we stumbled upon an old certificate policy
                final org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy policy = (org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy)o;
                CertificatePolicy newpolicy = new CertificatePolicy(policy.getPolicyID(), policy.getQualifierId(), policy.getQualifier());
                newpolicies.add(newpolicy);                    
            }
        }
        return newpolicies;
    }

    /** 
     * Checks if the column cAId column exists in AdminGroupData
     * 
     * @return true or false if the column exists or not
     */
    @Override
    public boolean checkColumnExists500() {
		// Try to find out if rowVersion exists and upgrade the PublisherQueueData in that case
		// This is needed since PublisherQueueData is a rather new table so it may have been created when the server started 
		// and we are upgrading from a not so new version
		final Connection connection = JDBCUtil.getDBConnection();
		boolean exists = false;
		try {
			final PreparedStatement stmt = connection.prepareStatement("select cAId from AdminGroupData where pk='0'");
			stmt.executeQuery();
			// If it did not throw an exception the column exists and we must run the post upgrade sql
			exists = true; 
			log.info("cAId column exists in AdminGroupData");
		} catch (SQLException e) {
			// Column did not exist
			log.info("cAId column does not exist in AdminGroupData");
			log.error(e);
		} finally {
			try {
				connection.close();
			} catch (SQLException e) {
				// do nothing
			}
		}
		return exists;
    }
    
    /**
     * Takes two versions and compares the first and the second versions to each other
     * 
     * @param first a version number
     * @param second a version number
     * @return true of the first version is lower (1.0 < 2.0) than the second, false otherwise. 
     */
    private boolean isLesserThan(final String first, final String second) {
        final String delimiter = "\\.";
        if (first == null) {
            if (second != null) {
                return true;    // No version is before a specified version
            }
            throw new IllegalArgumentException("First version argument may not be null");
        }
        if (second == null) {
            throw new IllegalArgumentException("Second version argument may not be null");
        }
        String[] firstSplit = first.split(delimiter);
        String[] secondSplit = second.split(delimiter);
        for (int i = 0; i < Math.max(firstSplit.length, secondSplit.length); i++) {
            if (i == firstSplit.length) {
                //We've gotten this far and passed the number of digits in first, so false
                return true;
            } else if (i == secondSplit.length) {
                return false;
            } else {
                String firstString = firstSplit[i].replaceAll("[^0-9].*", "");    // Remove trailing Beta2, _alpha1 etc
                if (firstString.isEmpty()) {
                    firstString = "0";  // Treat ".x" as ".0"
                }
                String secondString = secondSplit[i].replaceAll("[^0-9].*", "");
                if (secondString.isEmpty()) {
                    secondString = "0";
                }
                if (StringUtils.isNumeric(firstString) && StringUtils.isNumeric(secondString)) {
                    final int firstNumber = Integer.valueOf(firstString);
                    final int secondNumber = Integer.valueOf(secondString);
                    if (firstNumber != secondNumber) {
                        return firstNumber < secondNumber;
                    }
                } else {
                    throw new IllegalArgumentException("Unable to parse version numbers.");
                }
            }
        }
        //Versions must be the same then
        return false;
    }
}
