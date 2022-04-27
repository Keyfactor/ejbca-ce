/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.configuration;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.EABConfiguration;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;

/**
 * This bean handled global configurations.
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "GlobalConfigurationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class GlobalConfigurationSessionBean implements GlobalConfigurationSessionLocal, GlobalConfigurationSessionRemote {

    private static final Logger log = Logger.getLogger(GlobalConfigurationSessionBean.class);

    /**
     * Internal localization of logs and errors
     */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Properties getAllProperties(AuthenticationToken authenticationToken, String configID) throws AuthorizationDeniedException {
        assertAuthorization(authenticationToken, configID, "Could not read configuration.");
        return GlobalConfigurationCacheHolder.INSTANCE.getAllProperties(configID);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Set<String> getIds() {
        return GlobalConfigurationCacheHolder.INSTANCE.getIds();
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public ConfigurationBase getCachedConfiguration(final String configID) {
        ConfigurationBase result;
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getCachedConfiguration(" + configID + ")");
            }
            // Only do the actual SQL query if we might update the configuration due to cache time anyhow
            if (!GlobalConfigurationCacheHolder.INSTANCE.needsUpdate(configID)) {
                result = GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(configID);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Reading Configuration: " + configID);
                }
                final GlobalConfigurationData globalConfigurationData = findByConfigurationId(configID);
                if (globalConfigurationData == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("No default GlobalConfiguration exists. Creating a new one.");
                    }
                    // We create a new instance of the configuration, but we don't persist it (the first one to modify it will take care of it)
                    result = GlobalConfigurationCacheHolder.INSTANCE.getNewConfiguration(configID);
                } else {
                    result = GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(globalConfigurationData.getData(), configID);
                }
                // Always cache result
                GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(result, configID);
            }
            return result;
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<getCachedConfiguration(" + configID + ")");
            }
        }
    }

    @Override
    public void saveConfiguration(final AuthenticationToken authenticationToken, final ConfigurationBase conf) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveConfiguration()");
        }
        String configID = conf.getConfigurationId();
        assertAuthorization(authenticationToken, configID, "Could not save configuration");

        final GlobalConfigurationData gcdata = findByConfigurationId(configID);
        if (gcdata != null) {
            // Save object and create a diff over what has changed
            @SuppressWarnings("unchecked")
            final Map<Object, Object> orgmap = (Map<Object, Object>) GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(gcdata.getData(), configID).saveData();
            gcdata.setConfiguration(conf);
            GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(conf, configID);
            @SuppressWarnings("unchecked")
            final Map<Object, Object> newmap = (Map<Object, Object>) conf.saveData();
            // Get the diff of what changed
            final Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
            // Make security audit log record, but first have the object itself filter out any sensitive information
            conf.filterDiffMapForLogging(diff);
            final String msg = intres.getLocalizedMessage("globalconfig.savedconf", gcdata.getConfigurationId());
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                // Skip this because it can be too long in the case of a long EAB ID file.
                if (!"changed:eabmap".equals(entry.getKey().toString())
                    && !"changed:oauthkeys".equals(entry.getKey().toString())
                ){
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
            }
            // If applicable log all of the EAB namespaces and the number of IDs in each of them
            if (conf != null && conf.getClass().equals(EABConfiguration.class)) {
                for (Map.Entry<String,Set<String>> entry : ((EABConfiguration) conf).getEABMap().entrySet()) {
                    details.put("eabnamespace:" + entry.getKey(), entry.getValue().size());
                }
            }
            // If applicable log all of the OAuth providers
            if (conf != null && conf.getClass().equals(OAuthConfiguration.class)) {
                for (Map.Entry<String,OAuthKeyInfo> entry : ((OAuthConfiguration) conf).getOauthKeys().entrySet()) {
                    details.put("oauthkey_" + entry.getKey(), entry.getValue().createLogString());
                }
            }
            auditSession.log(EventTypes.SYSTEMCONF_EDIT, EventStatus.SUCCESS, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        } else {
            // Global configuration doesn't yet exist, so persist a new one.
            try {
                GlobalConfigurationData gcd = new GlobalConfigurationData(configID, conf);
                entityManager.persist(gcd);
                GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(conf, configID);
                final String msg = intres.getLocalizedMessage("globalconfig.createdconf", configID);
                auditSession.log(EventTypes.SYSTEMCONF_CREATE, EventStatus.SUCCESS, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                        authenticationToken.toString(), null, null, null, msg);
            } catch (Exception e) {
                final String msg = intres.getLocalizedMessage("globalconfig.errorcreateconf");
                log.info(msg, e);
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EventTypes.SYSTEMCONF_CREATE, EventStatus.FAILURE, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                        authenticationToken.toString(), null, null, null, details);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfiguration()");
        }
    }
    
    @Override
    public void saveConfigurationWithRootAccessCheck(final AuthenticationToken authenticationToken, final ConfigurationBase conf) throws AuthorizationDeniedException {
        final String accessRule = StandardRules.ROLE_ROOT.resource();
        if (!authorizationSession.isAuthorized(authenticationToken, accessRule)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", accessRule, "Could not save configuration");
            throw new AuthorizationDeniedException(msg);
        }
        saveConfiguration(authenticationToken, conf);
    }

    private void assertAuthorization(final AuthenticationToken authenticationToken, final String configID, final String errorMsg) throws AuthorizationDeniedException {
        final String accessRule = getAccessRuleFromConfigId(configID);
        if (!authorizationSession.isAuthorized(authenticationToken, accessRule)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", accessRule, errorMsg);
            throw new AuthorizationDeniedException(msg);
        }
    }

    /**
     * @return the access rule required to read the specified configuration type
     */
    private String getAccessRuleFromConfigId(final String configID) {
        switch (configID) {
            case AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID:
                return StandardRules.EKUCONFIGURATION_EDIT.resource();
            case AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID:
                return StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource();
            default:
                // NOPMD
        }
        return StandardRules.SYSTEMCONFIGURATION_EDIT.resource();
    }

    @Override
    public void flushConfigurationCache(final String configID) {
        if (log.isTraceEnabled()) {
            log.trace(">flushConfigurationCache(" + configID + ")");
        }
        GlobalConfigurationCacheHolder.INSTANCE.clearCache(configID);
        // Force cache to be loaded from the database unless another thread has already started to do it
        getCachedConfiguration(configID);
        if (log.isTraceEnabled()) {
            log.trace("<flushConfigurationCache(" + configID + ")");
        }
    }

    /**
     * @return the found entity instance or null if the entity does not exist
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public GlobalConfigurationData findByConfigurationId(String configurationId) {
        return entityManager.find(GlobalConfigurationData.class, configurationId);
    }

    private enum GlobalConfigurationCacheHolder {
        INSTANCE;

        private final Map<String, ConfigurationCache> caches = new ConcurrentHashMap<>();

        GlobalConfigurationCacheHolder() {
            ServiceLoader<? extends ConfigurationCache> serviceLoader = ServiceLoader.load(ConfigurationCache.class);
            // Extract all the caches from the plugin list
            for (ConfigurationCache cache : serviceLoader) {
                if (caches.containsKey(cache.getConfigId())) {
                    throw new IllegalStateException("Two caches loaded with the same config ID: " + cache.getConfigId()
                            + ". This is an invalid state.");
                } else {
                    caches.put(cache.getConfigId(), cache);
                }
            }
        }

        /**
         * @return all registered configuration IDs.
         */
        public Set<String> getIds() {
            return new HashSet<>(caches.keySet());
        }

        public void updateConfiguration(final ConfigurationBase conf, final String configId) {
            caches.get(configId).updateConfiguration(conf);
        }

        public void clearCache(final String configId) {
            caches.get(configId).clearCache();
        }

        public boolean needsUpdate(final String configId) {
            if (caches.get(configId) == null) {
                return true;
            }
            return caches.get(configId).needsUpdate();
        }

        public ConfigurationBase getConfiguration(final String configId) {
            final ConfigurationCache cache = caches.get(configId);
            if (cache != null) {
                return cache.getConfiguration();
            }
            return null;
        }

        @SuppressWarnings("rawtypes")
        public ConfigurationBase getConfiguration(final HashMap data, final String configId) {
            final ConfigurationCache cache = caches.get(configId);
            if (cache != null) {
                return cache.getConfiguration(data);
            }
            return null;
        }

        public ConfigurationBase getNewConfiguration(final String configId) {
            final ConfigurationCache cache = caches.get(configId);
            if (cache != null) {
                return cache.getNewConfiguration();
            }
            return null;
        }

        public Properties getAllProperties(final String configId) {
            final ConfigurationCache cache = caches.get(configId);
            if (cache != null) {
                return caches.get(configId).getAllProperties();
            }
            return null;
        }

    }
}


